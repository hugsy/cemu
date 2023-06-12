import os
from enum import Enum, unique
from typing import Optional

import unicorn
from PyQt6.QtCore import QMutex, QObject, QThread, pyqtSignal

import cemu.core
import cemu.utils
from cemu.log import dbg, error, info, log

from .arch import (Syntax, is_aarch64, is_arm, is_arm_thumb, is_mips,
                   is_mips64, is_ppc, is_sparc, is_sparc64, is_x86, is_x86_16,
                   is_x86_32, is_x86_64)
from .memory import MemorySection
from .utils import assemble, get_arch_mode


class EmulationInstance(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)

    def __init__(self, emu):
        super().__init__()
        self.emu: Emulator = emu

    def run(self) -> None:
        """
        Runs the emulation
        """
        if not self.emu.vm:
            error("VM is not ready")
            return

        info("Starting emulation context")

        try:
            if self.emu.use_step_mode:
                self.emu.set_vm_state(EmulatorState.STEP_RUNNING)
            else:
                self.emu.set_vm_state(EmulatorState.RUNNING)

            self.emu.vm.emu_start(self.emu.start_addr, self.emu.end_addr)

            if self.emu.pc() == self.emu.end_addr:
                self.emu.set_vm_state(EmulatorState.FINISHED)

        except unicorn.unicorn.UcError as e:
            error(f"An error occured: {str(e)}")
            log(f"pc={self.emu.pc():  # x} , sp={self.emu.sp():#x}")
            self.emu.set_vm_state(EmulatorState.FINISHED)

        self.finished.emit()
        return


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

    def __init__(self):
        self.use_step_mode = False
        self.widget = None
        self.vm_mutex = QMutex()
        self.reset()
        return

    def reset(self):
        self.vm: Optional[unicorn.Uc] = None
        self.code = None
        self.vm_state = EmulatorState.NOT_RUNNING
        self.stop_now = False
        self.num_insns = -1
        self.areas = {}
        self.registers = {}
        return

    def __str__(self) -> str:
        return f"Emulator instance {'' if self.is_running else 'not '}running"

    def unicorn_register(self, reg):
        curarch = cemu.core.context.architecture
        if is_x86(curarch):
            return getattr(unicorn.x86_const, "UC_X86_REG_%s" % reg.upper())

        if is_arm(curarch) or is_arm_thumb(curarch):
            return getattr(unicorn.arm_const, "UC_ARM_REG_%s" % reg.upper())

        if is_aarch64(curarch):
            return getattr(unicorn.arm64_const, "UC_ARM64_REG_%s" % reg.upper())

        # if is_ppc(curarch):
        #     return getattr(unicorn.ppc_const, "UC_PPC_REG_%s" % reg.upper())

        if is_mips(curarch) or is_mips64(curarch):
            return getattr(unicorn.mips_const, "UC_MIPS_REG_%s" % reg.upper())

        if is_sparc(curarch) or is_sparc64(curarch):
            return getattr(unicorn.sparc_const, "UC_SPARC_REG_%s" % reg.upper())

        raise Exception("Cannot find register '%s' for arch '%s'" %
                        (reg, curarch))

    def get_register_value(self, regname: str) -> int:
        """
        Returns an integer value of the register passed as a string.
        """
        if not self.vm:
            return -1

        self.vm_mutex.lock()
        ur = self.unicorn_register(regname)
        val = self.vm.reg_read(ur)
        self.vm_mutex.unlock()
        return val

    regs = get_register_value

    def pc(self) -> int:
        """
        Returns the current value of $pc
        """
        return self.get_register_value(cemu.core.context.architecture.pc)

    def sp(self) -> int:
        """
        Returns the current value of $sp
        """
        return self.get_register_value(cemu.core.context.architecture.sp)

    def unicorn_permissions(self, perms: str) -> int:
        """
        Returns the value as an integer of the permission mask given as input.
        """
        p = 0
        for perm in perms.split("|"):
            perm = perm.strip().upper()
            p |= getattr(unicorn, f"UC_PROT_{perm}")
        return p

    def create_new_vm(self) -> None:
        """
        Create a new VM, and sets up the hooks
        """
        arch, mode, endian = get_arch_mode("unicorn")
        self.vm = unicorn.Uc(arch, mode | endian)
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.vm.hook_add(unicorn.UC_HOOK_INTR, self.hook_interrupt)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        if is_x86(cemu.core.context.architecture):
            self.vm.hook_add(unicorn.UC_HOOK_INSN, self.hook_syscall,
                             None, 1, 0, unicorn.x86_const.UC_X86_INS_SYSCALL)
        return

    def populate_memory(self, areas: list[MemorySection]) -> bool:
        """
        Populates the VM memory layout according to the values given as parameter.
        """
        if not self.vm:
            error("VM is not initalized")
            return False

        for area in areas:
            name, address, size, permission, input_file = area.export()
            perm = self.unicorn_permissions(permission)
            self.vm.mem_map(address, size, perm)
            self.areas[name] = [address, size, permission, ]

            msg = "Map %s @%x (size=%d,perm=%s)" % (name,
                                                    address, size, permission)
            if input_file is not None and os.access(input_file, os.R_OK):
                code = open(input_file, 'rb').read()
                self.vm.mem_write(address, bytes(code[:size]))
                msg += " and content from '%s'" % input_file

            info(f"[vm::setup] {msg}")

        self.start_addr = self.areas[".text"][0]
        self.end_addr = -1
        return True

    def populate_registers(self, registers: dict[str, int]) -> bool:
        """
        Populates the VM memory layout according to the values given as parameter.
        """
        if not self.vm:
            return False

        arch = cemu.core.context.architecture

        for r in registers.keys():
            if is_x86_32(arch):
                # temporary hack for x86 segmentation issue
                if r in ('GS', 'FS', 'SS', 'DS', 'CS', 'ES'):
                    continue

            ur = self.unicorn_register(r)
            self.vm.reg_write(ur, registers[r])
            dbg(f"[vm::setup] Register '{r}' = {registers[r]:#x}")

        ur = self.unicorn_register(arch.pc)
        self.vm.reg_write(ur, self.areas[".text"][0])
        ur = self.unicorn_register(arch.sp)
        self.vm.reg_write(ur, self.areas[".stack"][0])
        return True

    def assemble_code(self, code: str, update_end_addr: bool = True) -> bool:
        """
        Compile the assembly code using Keystone. Returns True if all went well,
        False otherwise.
        """
        instructions = code.splitlines()
        nb_instructions = len(instructions)

        dbg(f"[vm::setup] Assembling {nb_instructions} instructions for {cemu.core.context.architecture.name}")
        self.code, self.num_insns = assemble(code)
        if self.num_insns < 0:
            error(f"Failed to compile: error at line {-self.num_insns:d}")
            return False

        if self.num_insns != nb_instructions:
            error(
                f"[vm::setup] Unexpected number of compiled instructions (got {self.num_insns}, compiled {nb_instructions})")
            return False

        dbg(f"[vm::setup] {self.num_insns} instruction{'s' if self.num_insns > 1 else ''} compiled: {len(self.code)} bytes")

        # update end_addr since we know the size of the code to execute
        if update_end_addr:
            self.end_addr = self.start_addr + len(self.code)
        return True

    def map_code(self) -> bool:
        if not self.vm:
            return False

        if ".text" not in self.areas.keys():
            error(
                "[vm::setup] Missing text area (add a .text section in the Mapping tab)")
            return False

        if self.code is None:
            error("[vm::setup] No code defined yet")
            return False

        addr = self.areas[".text"][0]
        info(f"Mapping .text at {addr:#x}")
        self.vm.mem_write(addr, bytes(self.code))
        return True

    def disassemble_one_instruction(self, code: bytearray, addr: int) -> str:
        """
        Returns a string disassembly of the first instruction from `code`.
        """
        arch = cemu.core.context.architecture
        for insn in cemu.utils.disassemble(code, 1, addr).values():
            return f"{insn[0], insn[1]}"

        raise Exception("should never be here")

    def hook_code(self, emu, address, size, user_data):
        """
        Unicorn instruction hook
        """
        if not self.vm:
            return False

        arch = cemu.core.context.architecture
        code = self.vm.mem_read(address, size)
        insn = self.disassemble_one_instruction(code, address)

        if self.stop_now:
            self.start_addr = self.get_register_value(arch.pc)
            emu.emu_stop()
            return

        dbg(f"[vm::runtime] Executing @ {address:#x}: {insn}")

        if self.use_step_mode:
            self.stop_now = True
        return

    def hook_block(self, emu, addr, size, misc):
        """
        Unicorn block change hook
        """
        dbg(f"[vm::runtime] Entering block at {addr:#x}")
        return

    def hook_interrupt(self, emu, intno, data):
        """
        Unicorn interrupt hook
        """
        dbg(f"[vm::runtime] Triggering interrupt #{intno:d}")
        return

    def hook_syscall(self, emu, user_data):
        """
        Unicorn syscall hook
        """
        dbg(f"[vm::runtime] Syscall")
        return

    def hook_mem_access(self, emu, access, address, size, value, _):
        if access == unicorn.UC_MEM_WRITE:
            info(f"Write: *{address:#x} = {value:#x} (size={size})")
        elif access == unicorn.UC_MEM_READ:
            info(f"Read: *{address:#x} (size={size})")
        return

    def run(self) -> None:
        """
        Runs the emulation
        """
        if not self.vm:
            error("VM is not ready")
            return

        self.thread = QThread()
        self.worker = EmulationInstance(self)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        return

    def __stop(self) -> None:
        """
        Stops the VM, frees the allocations
        """
        if not self.vm:
            return

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
        info("Ending emulation context")
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
        self.vm_mutex.lock()

        while True:
            dbg(f"Switching VM state from {self.vm_state} to {new_state}")
            self.vm_state = new_state

            if new_state == EmulatorState.NOT_RUNNING:
                cemu.core.context.root.signals["refreshRegisterGrid"].emit()
                cemu.core.context.root.signals["refreshMemoryEditor"].emit()
                cemu.core.context.root.signals["setCommandButtonStopState"].emit(
                )
                break

            if new_state == EmulatorState.RUNNING:
                cemu.core.context.root.signals["setCommandButtonsRunState"].emit(
                )
                break

            if new_state == EmulatorState.STEP_RUNNING:
                cemu.core.context.root.signals["refreshRegisterGrid"].emit()
                cemu.core.context.root.signals["refreshMemoryEditor"].emit()
                cemu.core.context.root.signals["setCommandButtonsStepRunState"].emit(
                )
                break

            break

        info(f"VM state is now {new_state}")

        self.vm_mutex.unlock()

        if new_state == EmulatorState.FINISHED:
            self.__finish()
        return

    @property
    def is_running(self) -> bool:
        return self.vm is not None and self.vm_state in (EmulatorState.RUNNING, EmulatorState.STEP_RUNNING)
