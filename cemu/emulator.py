import os

from typing import Dict, List, Tuple, Any
from enum import Enum, unique

import unicorn
import keystone
import capstone

from .arch import (
    Syntax,
    is_x86_16, is_x86_32, is_x86_64, is_x86,
    is_arm, is_arm_thumb, is_aarch64,
    is_mips, is_mips64,
    is_sparc, is_sparc64,
    is_ppc
)

from .utils import get_arch_mode, assemble

from .memory import MemorySection


@unique
class EmulatorState(Enum):
    NOT_RUNNING = 0
    IDLE = 1
    RUNNING = 2
    STEP_RUNNING = 3
    FINISHED = 4


class Emulator:
    EMU = 0
    LOG = 1

    def __init__(self, parent, *args, **kwargs):
        self.parent = parent
        self.root = self.parent
        self.arch = self.root.arch
        self.use_step_mode = False
        self.widget = None
        self.reset()
        return


    def reset(self):
        self.vm = None
        self.code = None
        self.__vm_state = EmulatorState.NOT_RUNNING
        self.stop_now = False
        self.num_insns = -1
        self.areas = {}
        self.registers = {}
        self.create_new_vm()
        return


    def __str__(self):
        return "Emulator instance {}running".format("" if self.is_running else "not ")


    def __xlog(self, wid, text, category):
        if wid==Emulator.EMU:
            msg = "{:1s} - {}".format(category, text)
        elif wid==Emulator.LOG:
            msg = "[{}] {} - {}".format("logger", category, text)
        else:
            raise Exception("Invalid widget")

        self.root.log(msg)
        return


    def pprint(self, x, category="Runtime"):
        return self.__xlog(Emulator.EMU, x, category)


    def log(self, x, category="Generic"):
        return self.__xlog(Emulator.LOG, x, category)


    def unicorn_register(self, reg):
        curarch = self.parent.arch
        if is_x86(curarch):
            return getattr(unicorn.x86_const, "UC_X86_REG_%s"%reg.upper())

        if is_arm(curarch) or is_arm_thumb(curarch):
            return getattr(unicorn.arm_const, "UC_ARM_REG_%s"%reg.upper())

        if is_aarch64(curarch):
            return getattr(unicorn.arm64_const, "UC_ARM64_REG_%s"%reg.upper())

        # if is_ppc(curarch):
        #     return getattr(unicorn.ppc_const, "UC_PPC_REG_%s" % reg.upper())

        if is_mips(curarch) or is_mips64(curarch):
            return getattr(unicorn.mips_const, "UC_MIPS_REG_%s" % reg.upper())

        if is_sparc(curarch) or is_sparc64(curarch):
            return getattr(unicorn.sparc_const, "UC_SPARC_REG_%s" %reg.upper())

        raise Exception("Cannot find register '%s' for arch '%s'" % (reg, curarch))


    def get_register_value(self, regname: str) -> int:
        """
        Returns an integer value of the register passed as a string.
        """
        ur = self.unicorn_register(regname)
        return self.vm.reg_read(ur)

    regs = get_register_value


    def pc(self) -> int:
        """
        Returns the current value of $pc
        """
        return self.get_register_value(self.root.arch.pc)


    def sp(self)-> int:
        """
        Returns the current value of $sp
        """
        return self.get_register_value(self.root.arch.sp)


    def unicorn_permissions(self, perms: str) -> int:
        """
        Returns the value as an integer of the permission mask given as input.
        """
        p = 0
        for perm in perms.split("|"):
            p |= getattr(unicorn, "UC_PROT_{}".format(perm.upper(),))
        return p


    def create_new_vm(self) -> None:
        """
        Create a new VM, and sets up the hooks
        """
        arch, mode, endian = get_arch_mode("unicorn", self.root.arch)
        self.vm = unicorn.Uc(arch, mode | endian)
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.vm.hook_add(unicorn.UC_HOOK_INTR, self.hook_interrupt)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        if is_x86(self.root.arch):
            self.vm.hook_add(unicorn.UC_HOOK_INSN, self.hook_syscall, None, 1, 0, unicorn.x86_const.UC_X86_INS_SYSCALL)
        return


    def populate_memory(self, areas: List[MemorySection]) -> bool:
        """
        Populates the VM memory layout according to the values given as parameter.
        """
        for area in areas:
            name, address, size, permission, input_file = area.export()
            perm = self.unicorn_permissions(permission)
            self.vm.mem_map(address, size, perm)
            self.areas[name] = [address, size, permission,]

            msg = "Map %s @%x (size=%d,perm=%s)" % (name, address, size, permission)
            if input_file is not None and os.access(input_file, os.R_OK):
                code = open(input_file, 'rb').read()
                self.vm.mem_write(address, bytes(code[:size]))
                msg += " and content from '%s'" % input_file

            self.log(msg, "Setup")

        self.start_addr = self.areas[".text"][0]
        self.end_addr = -1
        return True


    def populate_registers(self, registers: Dict[str, int]) -> bool:
        """
        Populates the VM memory layout according to the values given as parameter.
        """
        arch = self.root.arch
        for r in registers.keys():
            if is_x86_32(arch):
                # temporary hack for x86 segmentation issue
                if r in ('GS', 'FS', 'SS', 'DS', 'CS', 'ES'):
                    continue

            ur = self.unicorn_register(r)
            self.vm.reg_write(ur, registers[r])
            self.log("Register '{:s}' = {:#x}".format(r, registers[r]), "Setup")

        ur = self.unicorn_register(self.parent.arch.pc)
        self.vm.reg_write(ur, self.areas[".text"][0])
        ur = self.unicorn_register(self.parent.arch.sp)
        self.vm.reg_write(ur, self.areas[".stack"][0])
        return True


    def compile_code(self, code_list:List, update_end_addr:bool=True) -> bool:
        """
        Compile the assembly code using Keystone. Returns True if all went well,
        False otherwise.
        """
        n = len(code_list)
        code = b";".join(code_list)
        self.log("Assembling {} instructions for {}:\n{}".format(n, self.parent.arch.name, code), "Compilation")
        self.code, self.num_insns = assemble(code, self.parent.arch)
        if self.num_insns < 0:
            self.log("Failed to compile: error at line {:d}".format(-self.num_insns), "Error")
            return False

        if self.num_insns != n:
            self.log("Unexpected number of compiled instructions (got {}, compiled {})".format(self.num_insns,n), "Warning")

        self.log("{} instruction(s) compiled: {:d} bytes".format(self.num_insns, len(self.code)), "Compilation")

        # update end_addr since we know the size of the code to execute
        if update_end_addr:
            self.end_addr = self.start_addr + len(self.code)
        return True


    def map_code(self) -> None:
        if ".text" not in self.areas.keys():
            self.log("Missing text area (add a .text section in the Mapping tab)")
            return False

        if self.code is None:
            self.log("No code defined yet")
            return False

        addr = self.areas[".text"][0]
        self.log("Mapping .text at %#x" % addr, "Setup")
        self.vm.mem_write(addr, bytes(self.code))
        return True


    def disassemble_one_instruction(self, code: bytearray, addr: int) -> str:
        """
        Returns a string disassembly of the first instruction from `code`.
        """
        curarch = self.parent.arch
        arch, mode, endian = get_arch_mode("capstone", curarch)
        cs = capstone.Cs(arch, mode | endian)
        if is_x86(curarch) and curarch.syntax == Syntax.ATT:
            cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        for i in cs.disasm(bytes(code), addr):
            return i


    def hook_code(self, emu, address, size, user_data):
        """
        Unicorn instruction hook
        """
        code = self.vm.mem_read(address, size)
        insn = self.disassemble_one_instruction(code, address)

        if self.stop_now:
            self.start_addr = self.get_register_value(self.parent.arch.pc)
            emu.emu_stop()
            return

        self.log("Executing instruction at 0x{:x}".format(address), "Runtime")
        self.pprint("0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str), "Executing")

        if self.use_step_mode:
            self.stop_now = True
        return


    def hook_block(self, emu, addr, size, misc):
        """
        Unicorn block change hook
        """
        self.pprint("Entering block at 0x{:x}".format(addr), "Event")
        return


    def hook_interrupt(self, emu, intno, data):
        """
        Unicorn interrupt hook
        """
        self.pprint("Triggering interrupt #{:d}".format(intno), "Event")
        return


    def hook_syscall(self, emu, user_data):
        """
        Unicorn syscall hook
        """
        self.pprint("Syscall")
        return


    def hook_mem_access(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE:
            self.pprint("Write: *%#x = %#x (size = %u)"% (address, value, size), "Memory")
        elif access == unicorn.UC_MEM_READ:
            self.pprint("Read: *%#x (size = %u)" % (address, size), "Memory")
        return


    def run(self) -> None:
        """
        Runs the emulation
        """
        self.pprint("Starting emulation context")

        try:
            if self.use_step_mode:
                self.set_vm_state(EmulatorState.STEP_RUNNING)
            else:
                self.set_vm_state(EmulatorState.RUNNING)

            self.vm.emu_start(self.start_addr, self.end_addr)

            if self.pc()==self.end_addr:
                self.set_vm_state(EmulatorState.FINISHED)

        except unicorn.unicorn.UcError as e:
            self.log("An error occured: {}".format(str(e)), "Error")
            self.pprint("pc={:#x} , sp={:#x}: {:s}".format(self.pc(), self.sp(), str(e)), "Exception")
            self.set_vm_state(EmulatorState.FINISHED)

        return


    def __stop(self) -> None:
        """
        Stops the VM, frees the allocations
        """
        self.set_vm_state(EmulatorState.NOT_RUNNING)

        for area in self.areas.keys():
            addr, size = self.areas[area][0:2]
            self.vm.mem_unmap(addr, size)

        del self.vm
        self.vm = None
        return


    def __finish(self) -> None:
        """
        Clean up the emulator execution context.

        This internal function is called when the VM execution has finished, i.e.:
        1. an exception has occured in unicorn
        2. the emulator has reached the .text end address
        """
        self.pprint("Ending emulation context")
        self.__stop()
        return


    def lookup_map(self, mapname: str):
        """
        """
        for area in self.areas.keys():
            if area == mapname:
                return self.areas[area][0]
        raise KeyError("Section '{}' not found".format(mapname))


    def set_vm_state(self, new_state: EmulatorState) -> None:
        """
        Updates the internal state of the VM, and propagates the notification
        signals.
        """
        self.__vm_state = new_state

        if new_state == EmulatorState.NOT_RUNNING:
            self.root.signals["refreshRegisterGrid"].emit()
            self.root.signals["refreshMemoryEditor"].emit()
            self.root.signals["setCommandButtonStopState"].emit()
            return

        if new_state == EmulatorState.RUNNING:
            self.root.signals["setCommandButtonsRunState"].emit()
            return

        if new_state == EmulatorState.STEP_RUNNING:
            self.root.signals["refreshRegisterGrid"].emit()
            self.root.signals["refreshMemoryEditor"].emit()
            self.root.signals["setCommandButtonsStepRunState"].emit()
            return

        if new_state == EmulatorState.FINISHED:
            self.__finish()
            return

        return


    @property
    def is_running(self) -> bool:
        return self.__vm_state in (EmulatorState.RUNNING, EmulatorState.STEP_RUNNING)