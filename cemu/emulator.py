import unicorn
import keystone
import capstone

from .arch import Architecture

class Emulator:

    def __init__(self, mode, *args, **kwargs):
        self.mode = mode
        self.reinit()
        return

    def reinit(self):
        self.vm = None
        self.code = None
        self.widget = None
        self.areas = {}
        self.registers = {}
        self.create_new_vm()
        return


    def print(self, x):
        if self.widget is None:
            print(x)
            return
        self.widget.editor.append(x)
        return


    def get_arch_mode(self, lib):
        arch = mode = endian = None
        if   self.mode==Architecture.X86_16_INTEL or self.mode==Architecture.X86_16_ATT:
            if lib=="keystone":
                arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_16, keystone.KS_MODE_LITTLE_ENDIAN
            elif lib=="capstone":
                arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_16, capstone.CS_MODE_LITTLE_ENDIAN
            else:
                arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_16, unicorn.UC_MODE_LITTLE_ENDIAN

        elif self.mode==Architecture.X86_32_INTEL or self.mode==Architecture.X86_32_ATT:
            if lib=="keystone":
                arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_32, keystone.KS_MODE_LITTLE_ENDIAN
            elif lib=="capstone":
                arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_32, capstone.CS_MODE_LITTLE_ENDIAN
            else:
                arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, unicorn.UC_MODE_LITTLE_ENDIAN

        elif self.mode==Architecture.X86_64_INTEL or self.mode==Architecture.X86_64_ATT:
            if lib=="keystone":
                arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_64, keystone.KS_MODE_LITTLE_ENDIAN
            elif lib=="capstone":
                arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_64, capstone.CS_MODE_LITTLE_ENDIAN
            else:
                arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, unicorn.UC_MODE_LITTLE_ENDIAN

        if arch is None and mode is None and endian is None:
            raise Exception("Failed to get architecture parameter from mode")

        return arch, mode, endian


    def unicorn_register(self, reg):
        if self.mode in (Architecture.X86_16_INTEL, Architecture.X86_16_ATT,
                         Architecture.X86_32_INTEL, Architecture.X86_32_ATT,
                         Architecture.X86_64_INTEL, Architecture.X86_64_ATT):
            return getattr(unicorn.x86_const, "UC_X86_REG_%s"%reg.upper())

        raise Exception("Cannot find register '%s' for arch '%s'" % (reg, self.mode))


    def unicorn_permissions(self, perms):
        p = 0
        for perm in perms.split("|"):
            p |= getattr(unicorn, "UC_PROT_%s" % perm.upper())
        return p


    def create_new_vm(self):
        arch, mode, endian = self.get_arch_mode("unicorn")
        self.vm = unicorn.Uc(arch, mode | endian)
        return


    def populate_memory(self, areas):
        for name, address, size, permission in areas:
            perm = self.unicorn_permissions(permission)
            self.vm.mem_map(address, size, perm)
            self.areas[name] = [address, size, permission,]
            self.print(">>> map %s @%x (size=%d,perm=%s)" % (name, address, size, permission))
        return


    def populate_registers(self, registers):
        for r in registers.keys():
            ur = self.unicorn_register(r)
            self.vm.reg_write(ur, registers[r])
            self.print(">>> register %s = %x" % (r, registers[r]))
        return


    def compile_code(self, code):
        arch, mode, endian = self.get_arch_mode("keystone")
        ks = keystone.Ks(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        code = b";".join(code)
        self.print(">>> Compiling '%s'" % code)
        code, cnt = ks.asm(code)
        self.code = bytes(bytearray(code))
        self.print(">>> %d instructions compiled" % cnt)
        return


    def map_code(self):
        if ".text" not in self.areas.keys():
            raise Exception("Missing text area")
        if self.code is None:
            raise Exception("No code defined yet")
        addr = self.areas[".text"][0]
        self.print(">>> mapping .text at %#x" % addr)
        self.vm.mem_write(addr, bytes(self.code))
        return


    def disassemble(self, code, addr):
        arch, mode, endian = self.get_arch_mode("capstone")
        cs = capstone.Cs(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        for i in cs.disasm(bytes(code), addr):
            return i


    def hook_code(self, emu, address, size, user_data):
        self.print(">> Executing instruction at 0x{:x}".format(address))
        code = self.vm.mem_read(address, size)
        insn = self.disassemble(code, address)
        self.print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
        return


    def hook_block(self, emu, addr, size, misc):
        return


    def run(self):
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

        start_addr = self.areas[".text"][0]
        end_addr = start_addr + len(self.code)
        try:
            self.vm.emu_start(start_addr, end_addr)
        except unicorn.UcError as e:
            self.vm.emu_stop()
            self.print("An error occured during emulation: %s" % e)
            return

        self.print(">>> End of emulation")
        return


    def stop(self):
        del self.vm
        self.vm = None
        return
