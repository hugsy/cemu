import unicorn
import keystone
import capstone

from .arch import Architecture
from .utils import get_arch_mode


class Emulator:

    def __init__(self, mode, *args, **kwargs):
        self.mode = mode
        self.use_step_mode = False
        self.reinit()
        return


    def reinit(self):
        self.vm = None
        self.code = None
        self.widget = None
        self.is_running = False
        self.stop_now = False
        self.areas = {}
        self.registers = {}
        self.create_new_vm()
        return


    def print(self, x):
        if self.widget is None:
            print(x)
        else:
            self.widget.emuWidget.editor.append(x)
        return


    def log(self, x):
        if self.widget is None:
            print(x)
        else:
            self.widget.logWidget.editor.append(x)
        return


    def unicorn_register(self, reg):
        if self.mode in (Architecture.X86_16_INTEL, Architecture.X86_16_ATT,
                         Architecture.X86_32_INTEL, Architecture.X86_32_ATT,
                         Architecture.X86_64_INTEL, Architecture.X86_64_ATT):
            return getattr(unicorn.x86_const, "UC_X86_REG_%s"%reg.upper())

        if self.mode in (Architecture.ARM_LE, Architecture.ARM_BE,
                         Architecture.ARM_THUMB_LE, Architecture.ARM_THUMB_BE):
            return getattr(unicorn.arm_const, "UC_ARM_REG_%s"%reg.upper())

        if self.mode==Architecture.ARM_AARCH64:
            return getattr(unicorn.arm64_const, "UC_ARM_REG64_%s"%reg.upper())

        if self.mode in (Architecture.MIPS, Architecture.MIPS_BE,
                         Architecture.MIPS64, Architecture.MIPS64_BE):
            return getattr(unicorn.arm_const, "UC_ARM_REG_%s"%reg.upper())

        if self.mode in (Architecture.SPARC, Architecture.SPARC64_BE):
            return getattr(unicorn.arm_const, "UC_ARM_REG_%s"%reg.upper())

        # todo add arch arm/aarch/mips/mips64/sparc/sparc64

        raise Exception("Cannot find register '%s' for arch '%s'" % (reg, self.mode))


    def get_register_value(self, r):
        ur = self.unicorn_register(r)
        return self.vm.reg_read(ur)


    def unicorn_permissions(self, perms):
        p = 0
        for perm in perms.split("|"):
            p |= getattr(unicorn, "UC_PROT_%s" % perm.upper())
        return p


    def create_new_vm(self):
        arch, mode, endian = get_arch_mode("unicorn", self.mode)
        self.vm = unicorn.Uc(arch, mode | endian)
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.vm.hook_add(unicorn.UC_HOOK_INTR, self.hook_interrupt)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        return


    def populate_memory(self, areas):
        for name, address, size, permission in areas:
            perm = self.unicorn_permissions(permission)
            self.vm.mem_map(address, size, perm)
            self.areas[name] = [address, size, permission,]
            self.log(">>> map %s @%x (size=%d,perm=%s)" % (name, address, size, permission))

        self.start_addr = self.areas[".text"][0]
        self.end_addr = -1
        return


    def populate_registers(self, registers):
        for r in registers.keys():
            ur = self.unicorn_register(r)
            self.vm.reg_write(ur, registers[r])
            self.log(">>> register %s = %x" % (r, registers[r]))

        # fix $PC
        ur = self.unicorn_register(self.mode.get_pc())
        self.vm.reg_write(ur, self.areas[".text"][0])

        # fix $SP
        ur = self.unicorn_register(self.mode.get_sp())
        self.vm.reg_write(ur, self.areas[".stack"][0])
        return


    def compile_code(self, code, update_end_addr=True):
        arch, mode, endian = get_arch_mode("keystone", self.mode)
        ks = keystone.Ks(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        code = b" ; ".join(code)
        self.log(">>> Assembly using keystone: %s" % code)
        try:
            code, cnt = ks.asm(code)
            if cnt == 0:
                self.code = b""
            else:
                self.code = bytes(bytearray(code))
                self.log(">>> %d instructions compiled" % cnt)

        except keystone.keystone.KsError:
            self.log(">>> Failed to compile code")
            self.code = b""
            return

        # update end_addr since we know the size of the code to execute
        if update_end_addr:
            self.end_addr = self.start_addr + len(self.code)
        return


    def map_code(self):
        if ".text" not in self.areas.keys():
            raise Exception("Missing text area")
        if self.code is None:
            raise Exception("No code defined yet")
        addr = self.areas[".text"][0]
        self.log(">>> mapping .text at %#x" % addr)
        self.vm.mem_write(addr, bytes(self.code))
        return


    def disassemble_one_instruction(self, code, addr):
        arch, mode, endian = get_arch_mode("capstone", self.mode)
        cs = capstone.Cs(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        for i in cs.disasm(bytes(code), addr):
            return i


    def hook_code(self, emu, address, size, user_data):
        code = self.vm.mem_read(address, size)
        insn = self.disassemble_one_instruction(code, address)

        if self.stop_now:
            self.start_addr = self.get_register_value(self.mode.get_pc())
            emu.emu_stop()
            return

        self.log(">> Executing instruction at 0x{:x}".format(address))
        self.print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))

        if self.use_step_mode:
            self.stop_now = True
        return


    def hook_block(self, emu, addr, size, misc):
        self.print(">>> Entering new block at 0x{:x}".format(addr))
        return


    def hook_interrupt(self, emu, intno, data):
        self.print(">>> Triggering interrupt #{:d}".format(intno))
        return


    def hook_mem_access(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE:
            self.print(">>> MEM_WRITE : *%#x = %#x (size = %u)"% (address, value, size))
        elif access == unicorn.UC_MEM_READ:
            self.print(">>> MEM_READ : reg = *%#x (size = %u)" % (address, size))
        return


    def run(self):
        self.print(">>> Execution from %#x to %#x" % (self.start_addr, self.end_addr))
        try:
            self.vm.emu_start(self.start_addr, self.end_addr)
        except unicorn.unicorn.UcError as e:
            self.vm.emu_stop()
            self.log("An error occured during emulation")
            return

        if self.get_register_value( self.mode.get_pc() )==self.end_addr:
            self.print(">>> End of emulation")
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
