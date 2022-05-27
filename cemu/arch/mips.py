from cemu.arch import Architecture, Endianness


class MIPS(Architecture):
    name: str = "MIPS 32bits"
    pc: str = "PC"
    sp: str = "SP"
    flag = None
    registers: list[str] = [
        "ZERO", "AT", "V0", "V1",
        'A0', 'A1', 'A2', 'A3',
        'S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8',
        'T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8', 'T9',
        "K0", "K1", "HI", "LO", "GP", "RA",
        sp,
        pc,
    ]
    syscall_filename: str = "mips"
    ptrsize: int = 4

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.get("endian", Endianness.LITTLE_ENDIAN)
        return


class MIPS64(MIPS):
    ptrsize = 8
    name = "MIPS 64bits"
