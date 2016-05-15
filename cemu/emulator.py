import unicorn
import keystone
import capstone

from .arch import Architecture

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


    def get_register_value(self, r):
        ur = self.unicorn_register(r)
        return self.vm.reg_read(ur)


    def unicorn_permissions(self, perms):
        p = 0
        for perm in perms.split("|"):
            p |= getattr(unicorn, "UC_PROT_%s" % perm.upper())
        return p


    def create_new_vm(self):
        arch, mode, endian = self.get_arch_mode("unicorn")
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


    def compile_code(self, code):
        arch, mode, endian = self.get_arch_mode("keystone")
        ks = keystone.Ks(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        code = b";".join(code)
        self.log(">>> Assembly using keystone: '%s'" % code)
        code, cnt = ks.asm(code)
        self.code = bytes(bytearray(code))
        self.log(">>> %d instructions compiled" % cnt)

        # update end_addr since we know the size of the code to execute
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


    def disassemble(self, code, addr):
        arch, mode, endian = self.get_arch_mode("capstone")
        cs = capstone.Cs(arch, mode | endian)
        if self.mode in (Architecture.X86_16_ATT, Architecture.X86_32_ATT, Architecture.X86_64_ATT):
            cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        for i in cs.disasm(bytes(code), addr):
            return i


    def hook_code(self, emu, address, size, user_data):
        self.log(">> Executing instruction at 0x{:x}".format(address))
        code = self.vm.mem_read(address, size)
        insn = self.disassemble(code, address)
        self.print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))

        if self.use_step_mode:
            emu.emu_stop()
            self.start_addr = self.get_register_value(self.mode.get_pc()) + insn.size
            self.log("next start_addr = %#x"  % self.start_addr)
        return


    def hook_block(self, emu, addr, size, misc):
        self.print(">>> Entering new block at 0x{:x}".format(addr))
        return


    def hook_block(self, emu, addr, size, misc):
        self.print(">>> Entering new block at 0x{:x}".format(addr))
        return


    def hook_interrupt(self, emu, intno, data):
        self.print(">>> Triggering interrupt #{:d}".format(intno))
        return


    def hook_mem_access(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE:
            self.print(">>> MEM_WRITE : *%#x = 0x%#x (size = %u)"% (address, value, size))
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
