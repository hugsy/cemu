from cemu.arch import Architecture, Endianness, Syntax


class ARM(Architecture):
    # http://www.keil.com/support/man/docs/armasm/armasm_dom1359731128950.htm

    pc   = "PC"
    sp   = "SP"
    flag = "CPSR"
    registers = [
        'R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R12', # GPR
        "FP", "LR",
        flag,
        pc,
        sp,
    ]
    syscall_filename = "arm"

    def __init__(self, *args, **kwargs):
        self.thumb = kwargs.get("thumb", False)
        self.endianness = kwargs.get("endian", Endianness.LITTLE)
        return

    @property
    def ptrsize(self):
        if self.thumb: return 2
        return 4

    @property
    def syscall_filename(self):
        if self.thumb: return "arm-thumb"
        return "arm"

    @property
    def name(self):
        if self.thumb: return "ARM THUMB mode"
        return "ARM Native mode"


class AARCH64(Architecture):
    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0801a/BABIBIGB.html
    name = "ARM AARCH64"
    pc   = "PC"
    sp   = "SP"
    flag = "NZCV"
    endianness = Endianness.LITTLE
    registers = [
        'X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7',
        'X8', 'X9', 'X10', 'X11', 'X12', 'X13', 'X14', 'X15',
        'X16', 'X17', 'X18', 'X19', 'X20', 'X21', 'X22', 'X23',
        'X24', 'X25', 'X26', 'X27', 'X28', 'X29', 'X30',
        flag,
        pc
    ]
    syscall_filename = "aarch64"
