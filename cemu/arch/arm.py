import capstone
import keystone
import unicorn

from cemu.arch import Architecture, Endianness


class ARM(Architecture):
    # http://www.keil.com/support/man/docs/armasm/armasm_dom1359731128950.htm
    pc = "PC"
    sp = "SP"
    flag = "CPSR"
    registers = [
        "R0",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        "R8",
        "R9",
        "R10",
        "R12",  # GPR
        "FP",
        "LR",
        flag,
        pc,
        sp,
    ]
    syscall_filename = "arm"

    def __init__(self, *args, **kwargs):
        self.thumb = kwargs.get("thumb", False)
        self.endianness = kwargs.get("endian", Endianness.LITTLE_ENDIAN)
        return

    @property
    def ptrsize(self):
        if self.thumb:
            return 2
        return 4

    @property
    def syscall_filename(self):
        if self.thumb:
            return "arm-thumb"
        return "arm"

    @property
    def name(self):
        if self.thumb:
            return "ARM THUMB mode"
        return "ARM Native mode"

    def keystone(self) -> tuple[int, int, int]:
        if self.thumb:
            return (
                keystone.KS_ARCH_ARM,
                keystone.KS_MODE_THUMB,
                keystone.KS_MODE_LITTLE_ENDIAN,
            )
        return (
            keystone.KS_ARCH_ARM,
            keystone.KS_MODE_ARM,
            keystone.KS_MODE_LITTLE_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        if self.thumb:
            return (
                capstone.CS_ARCH_ARM,
                capstone.CS_MODE_THUMB,
                capstone.CS_MODE_LITTLE_ENDIAN,
            )
        return (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_ARM,
            capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        if self.thumb:
            return (
                unicorn.UC_ARCH_ARM,
                unicorn.UC_MODE_THUMB,
                unicorn.UC_MODE_LITTLE_ENDIAN,
            )
        return (
            unicorn.UC_ARCH_ARM,
            unicorn.UC_MODE_ARM,
            unicorn.UC_MODE_LITTLE_ENDIAN,
        )

    def uc_register(self, name: str) -> int:
        return getattr(unicorn.arm_const, f"UC_ARM_REG_{name.upper()}")


class AARCH64(Architecture):
    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0801a/BABIBIGB.html
    # https://llvm.org/devmtg/2012-11/Northover-AArch64.pdf
    name = "ARM AARCH64"
    pc = "PC"
    sp = "SP"
    flag = "NZCV"
    endianness = Endianness.LITTLE_ENDIAN
    registers = [
        "X0",
        "X1",
        "X2",
        "X3",
        "X4",
        "X5",
        "X6",
        "X7",
        "X8",
        "X9",
        "X10",
        "X11",
        "X12",
        "X13",
        "X14",
        "X15",
        "X16",
        "X17",
        "X18",
        "X19",
        "X20",
        "X21",
        "X22",
        "X23",
        "X24",
        "X25",
        "X26",
        "X27",
        "X28",
        "X29",
        "X30",
        sp,
        flag,
        pc,
    ]
    syscall_filename = "aarch64"
    ptrsize = 8
    ptrsize = 8

    def keystone(self) -> tuple[int, int, int]:
        return (keystone.KS_ARCH_ARM64, 0, keystone.KS_MODE_LITTLE_ENDIAN)

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_ARM64,
            capstone.CS_MODE_ARM,
            capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_ARM64,
            unicorn.UC_MODE_ARM,
            unicorn.UC_MODE_LITTLE_ENDIAN,
        )

    def uc_register(self, name: str) -> int:
        return getattr(unicorn.arm64_const, f"UC_ARM64_REG_{name.upper()}")
