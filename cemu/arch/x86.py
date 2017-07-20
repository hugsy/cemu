from cemu.arch import Architecture, Endianness, Syntax


class X86(Architecture):
    name = "Intel 8086 16bit"
    pc   = "IP"
    sp   = "SP"
    flag = "EFLAGS"
    pgr_registers = ["CS", "DS", "ES", "FS", "GS", "SS",]
    registers = [
        "AX", "BX", "CX", "DX", "SI", "DI", "BP",                 # GPR
        pc,
        sp,
        flag,
    ] + pgr_registers
    ptrsize = 2
    syscall_filename = "x86"

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.get("endian", Endianness.LITTLE)
        self.syntax = kwargs.get("syntax", Syntax.INTEL)
        return


    def __str__(self):
        return "{}, syntax {} - {} endian".format(self.name,
                                                  "ATT" if self.syntax==Syntax.ATT else "Intel",
                                                  self.endian_str)


class X86_32(X86):
    name = "Intel i386 32bit"
    pc   = "EIP"
    sp   = "ESP"
    registers = [
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP",                 # GPR
        pc,
        sp,
        X86.flag,
    ] + X86.pgr_registers
    ptrsize = 4


class X86_64(X86):
    name = "Intel i386 64bit"
    pc   = "RIP"
    sp   = "RSP"
    registers = [
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP",                 # GPR
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R14", "R15",
        pc,
        sp,
        X86.flag,
    ] + X86.pgr_registers
    ptrsize = 8
    syscall_filename = "x86-64"
