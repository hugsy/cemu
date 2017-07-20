from cemu.arch import Architecture, Endianness, Syntax


class SPARC(Architecture):
    name = "SPARC 32bits"
    pc   = "PC"
    sp   = "SP"
    flag = "ICC"
    registers = [
        'G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7',
        'L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7',
        'I0', 'I1', 'I2', 'I3', 'I4', 'I5', 'I6', 'I7',
        'O0', 'O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O7',
        flag,
        pc,
    ]
    syscall_filename = "sparc"
    ptrsize = 4
    endianness = Endianness.LITTLE


class SPARC64(SPARC):
    ptrsize = 8
    name = "SPARC 64bits"
