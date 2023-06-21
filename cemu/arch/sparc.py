import capstone
import keystone
import unicorn

from cemu.arch import Architecture, Endianness


class SPARC(Architecture):
    name: str = "SPARC 32bits"
    pc: str = "PC"
    sp: str = "SP"
    flag: str = "ICC"
    registers: list[str] = [
        "G0",
        "G1",
        "G2",
        "G3",
        "G4",
        "G5",
        "G6",
        "G7",
        "L0",
        "L1",
        "L2",
        "L3",
        "L4",
        "L5",
        "L6",
        "L7",
        "I0",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
        "I6",
        "I7",
        "O0",
        "O1",
        "O2",
        "O3",
        "O4",
        "O5",
        "O6",
        "O7",
        flag,
        pc,
        sp,
    ]
    syscall_filename: str = "sparc"
    ptrsize: int = 4
    endianness = Endianness.BIG_ENDIAN

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_SPARC,
            keystone.KS_MODE_SPARC32,
            keystone.KS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else keystone.KS_MODE_BIG_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_SPARC,
            0,
            capstone.CS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else capstone.CS_MODE_BIG_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_SPARC,
            unicorn.UC_MODE_SPARC32,
            unicorn.UC_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else unicorn.UC_MODE_BIG_ENDIAN,
        )

    def uc_register(self, name: str) -> int:
        return getattr(unicorn.sparc_const, f"UC_SPARC_REG_{name.upper()}")


class SPARC64(SPARC):
    ptrsize = 8
    name = "SPARC 64bits"

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_SPARC,
            keystone.KS_MODE_SPARC64,
            keystone.KS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else keystone.KS_MODE_BIG_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_SPARC,
            capstone.CS_MODE_64,
            capstone.CS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else capstone.CS_MODE_BIG_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_SPARC,
            unicorn.UC_MODE_SPARC64,
            unicorn.UC_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else unicorn.UC_MODE_BIG_ENDIAN,
        )
