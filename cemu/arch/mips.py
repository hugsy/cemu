import capstone
import keystone
import unicorn

from cemu.arch import Architecture, Endianness


class MIPS(Architecture):
    name: str = "MIPS 32bits"
    pc: str = "PC"
    sp: str = "SP"
    flag = None
    registers: list[str] = [
        "ZERO",
        "AT",
        "V0",
        "V1",
        "A0",
        "A1",
        "A2",
        "A3",
        "S0",
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
        "S7",
        "S8",
        "T0",
        "T1",
        "T2",
        "T3",
        "T4",
        "T5",
        "T6",
        "T7",
        "T8",
        "T9",
        "K0",
        "K1",
        "HI",
        "LO",
        "GP",
        "RA",
        sp,
        pc,
    ]
    syscall_filename: str = "mips"
    ptrsize: int = 4

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.get("endian", Endianness.LITTLE_ENDIAN)
        return

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_MIPS,
            keystone.KS_MODE_MIPS32,
            keystone.KS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else keystone.KS_MODE_BIG_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_MIPS,
            capstone.CS_MODE_MIPS32,
            capstone.CS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else capstone.CS_MODE_BIG_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_MIPS,
            unicorn.UC_MODE_MIPS32,
            unicorn.UC_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else unicorn.UC_MODE_BIG_ENDIAN,
        )

    def uc_register(self, name: str) -> int:
        return getattr(unicorn.mips_const, f"UC_MIPS_REG_{name.upper()}")


class MIPS64(MIPS):
    ptrsize = 8
    name = "MIPS 64bits"
    name = "MIPS 64bits"

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_MIPS,
            keystone.KS_MODE_MIPS64,
            keystone.KS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else keystone.KS_MODE_BIG_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_MIPS,
            capstone.CS_MODE_MIPS64,
            capstone.CS_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else capstone.CS_MODE_BIG_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_MIPS,
            unicorn.UC_MODE_MIPS64,
            unicorn.UC_MODE_LITTLE_ENDIAN
            if self.endianness == Endianness.LITTLE_ENDIAN
            else unicorn.UC_MODE_BIG_ENDIAN,
        )
