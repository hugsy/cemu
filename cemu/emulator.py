import os

import unicorn
import keystone
import capstone

from cemu.arch import Syntax, \
    is_x86_16, is_x86_32, is_x86_64, is_x86, \
    is_arm, is_arm_thumb, is_aarch64, \
    is_mips, is_mips64, \
    is_sparc, is_sparc64, \
    is_ppc

from .utils import get_arch_mode, assemble


class Emulator:
    EMU = 0
    LOG = 1

    def __init__(self, parent, *args, **kwargs):
        self.parent = parent
        self.use_step_mode = False
        self.widget = None
        self.reinit()
        return


    def reinit(self):
        self.vm = None
        self.code = None
        self.is_running = False
        self.stop_now = False
        self.num_insns = -1
        self.areas = {}
        self.registers = {}
        self.create_new_vm()
        return

    def __str__(self):
        return "Emulator instance {}running".format("" if self.is_running else "not ")

    def __xlog(self, wid, text, category):
        if self.widget is None:
            print("{} - {}".format(category, text))
            return

        if   wid==Emulator.EMU:
            widget = self.widget.emuWidget
            msg = "{:1s} - {}".format(category, text)
        elif wid==Emulator.LOG:
            widget = self.widget.logWidget
            msg = "[{}] {} - {}".format("logger", category, text)
        else:
            raise Exception("Invalid widget")

        widget.editor.append(msg)
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

        if is_ppc(curarch):
            return getattr(unicorn.ppc_const, "UC_PPC_REG_%s" % reg.upper())

        if is_mips(curarch) or is_mips64(curarch):
            return getattr(unicorn.mips_const, "UC_MIPS_REG_%s" % reg.upper())

        if is_sparc(curarch) or is_sparc64(curarch):
            return getattr(unicorn.sparc_const, "UC_SPARC_REG_%s" %reg.upper())

        raise Exception("Cannot find register '%s' for arch '%s'" % (reg, curarch))


    def get_register_value(self, r):
        ur = self.unicorn_register(r)
        return self.vm.reg_read(ur)


    def pc(self):
        return self.get_register_value(self.parent.arch.pc)


    def sp(self):
        return self.get_register_value(self.parent.arch.sp)


    def unicorn_permissions(self, perms):
        p = 0
        for perm in perms.split("|"):
            p |= getattr(unicorn, "UC_PROT_%s" % perm.upper())
        return p


    def create_new_vm(self):
        arch, mode, endian = get_arch_mode("unicorn", self.parent.arch)
        self.vm = unicorn.Uc(arch, mode | endian)
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.vm.hook_add(unicorn.UC_HOOK_INTR, self.hook_interrupt)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        return


    def populate_memory(self, areas):
        for name, address, size, permission, input_file in areas:
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


    def populate_registers(self, registers):
        for r in registers.keys():
            ur = self.unicorn_register(r)
            self.vm.reg_write(ur, registers[r])
            self.log("Register '{:s}' = {:#x}".format(r, registers[r]), "Setup")

        # fix $PC
        ur = self.unicorn_register(self.parent.arch.pc)
        self.vm.reg_write(ur, self.areas[".text"][0])

        # fix $SP
        ur = self.unicorn_register(self.parent.arch.sp)
        self.vm.reg_write(ur, self.areas[".stack"][0])
        return True


    def compile_code(self, code_list, update_end_addr=True):
        n = len(code_list)
        code = b" ; ".join(code_list)
        self.log("Assembling {} instructions for {}:\n{}".format(n, self.parent.arch.name, code), "Compilation")
        self.code, self.num_insns = assemble(code, self.parent.arch)
        if self.num_insns == -1:
            self.log("Failed to compile code", "Error")
            return False

        if self.num_insns != n:
            self.log("Unexpected number of compiled instructions (got {}, compiled {})".format(self.num_insns,n), "Warning")

        self.log("{} instruction(s) compiled".format(self.num_insns), "Compilation")

        # update end_addr since we know the size of the code to execute
        if update_end_addr:
            self.end_addr = self.start_addr + len(self.code)
        return True


    def map_code(self):
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


    def disassemble_one_instruction(self, code, addr):
        curarch = self.parent.arch
        arch, mode, endian = get_arch_mode("capstone", curarch)
        cs = capstone.Cs(arch, mode | endian)
        if is_x86(curarch) and curarch.syntax == Syntax.ATT:
            cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        for i in cs.disasm(bytes(code), addr):
            return i


    def hook_code(self, emu, address, size, user_data):
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
        self.pprint("Entering new block at 0x{:x}".format(addr), "Event")
        return


    def hook_interrupt(self, emu, intno, data):
        self.pprint("Triggering interrupt #{:d}".format(intno), "Event")
        return


    def hook_mem_access(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE:
            self.pprint("Write: *%#x = %#x (size = %u)"% (address, value, size), "Memory")
        elif access == unicorn.UC_MEM_READ:
            self.pprint("Read: *%#x (size = %u)" % (address, size), "Memory")
        return


    def run(self):
        self.pprint("Starting emulation context")
        try:
            self.vm.emu_start(self.start_addr, self.end_addr)
        except unicorn.unicorn.UcError as e:
            self.log("An error occured: {}".format(str(e)), "Error")
            self.pprint("pc={:#x} , sp={:#x}: {:s}".format(self.pc(), self.sp(), str(e)), "Exception")
            self.vm.emu_stop()
            return

        if self.pc()==self.end_addr:
            self.pprint("Ending emulation context")
            self.widget.commandWidget.runButton.setDisabled(True)
            self.widget.commandWidget.stepButton.setDisabled(True)
        return


    def stop(self):
        for area in self.areas.keys():
            addr, size = self.areas[area][0:2]
            self.vm.mem_unmap(addr, size)

        del self.vm
        self.vm = None
        self.is_running = False
        return


    def lookup_map(self, mapname):
        for area in self.areas.keys():
            if area == mapname:
                return self.areas[area][0]
        return None
