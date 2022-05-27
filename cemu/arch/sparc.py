from cemu.arch import Architecture, Endianness, Syntax


class SPARC(Architecture):
    name: str = "SPARC 32bits"
    pc: str = "PC"
    sp: str = "SP"
    flag: str = "ICC"
    registers: list[str] = [
        'G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7',
        'L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7',
        'I0', 'I1', 'I2', 'I3', 'I4', 'I5', 'I6', 'I7',
        'O0', 'O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O7',
        flag,
        pc,
    ]
    syscall_filename: str = "sparc"
    ptrsize: int = 4
    endianness = Endianness.LITTLE_ENDIAN


class SPARC64(SPARC):
    ptrsize = 8
    name = "SPARC 64bits"
