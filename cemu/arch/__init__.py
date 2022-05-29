import enum
import importlib
from typing import Optional

from cemu.const import SYSCALLS_PATH


class Endianness(enum.Enum):
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Syntax(enum.Enum):
    INTEL = 1
    ATT = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Architecture:
    """Generic metaclass for the architectures."""
    name: str
    endianness: Endianness = Endianness.LITTLE_ENDIAN
    syntax: Syntax = Syntax.INTEL
    registers: list[str]
    instruction_length: int
    flag: Optional[str]
    pc: str
    sp: str
    ptrsize: int
    regsize: int
    syscall_filename: str

    def __repr__(self):
        return f"{self.name} (Ptrsize={self.ptrsize}, Endian={self.endianness}, Syntax={self.syntax})"

    def __str__(self):
        return f"{self.name}"

    __syscalls: Optional[dict[str, int]] = None
    syscall_base = 0

    @property
    def syscalls(self):
        if not self.__syscalls:
            fpath = SYSCALLS_PATH / (self.syscall_filename + ".csv")
            self.__syscalls = {}

            with fpath.open('r') as fd:
                for row in fd.readlines():
                    row = [x.strip() for x in row.strip().split(',')]
                    syscall_number = int(row[0])
                    syscall_name = row[1].lower()
                    self.__syscalls[syscall_name] = self.syscall_base + \
                        syscall_number

        return self.__syscalls

    def __eq__(self, x):
        if not isinstance(x, Architecture):
            return False
        return self.name == x.name and self.endianness == x.endianness and self.syntax == x.syntax


class ArchitectureManager(dict[str, list[Architecture]]):

    def __init__(self):
        super().__init__()
        self.load(True)

    def load(self, force_reload: bool = False) -> None:
        """Instanciate all the architecture objects
        """
        if force_reload:
            generic = importlib.import_module(".generic", package="cemu.arch")
            x86 = importlib.import_module(".x86", package="cemu.arch")
            arm = importlib.import_module(".arm", package="cemu.arch")
            mips = importlib.import_module(".mips", package="cemu.arch")
            sparc = importlib.import_module(".sparc", package="cemu.arch")

            self["generic"] = [generic.Generic(), ]
            self["x86"] = [x86.X86(), x86.X86_32(), x86.X86_64(), x86.X86(
                syntax=Syntax.ATT), x86.X86_32(syntax=Syntax.ATT), x86.X86_64(syntax=Syntax.ATT)]
            self["arm"] = [arm.ARM(), arm.ARM(thumb=True), arm.AARCH64()]
            self["mips"] = [mips.MIPS(), mips.MIPS(endian=Endianness.BIG_ENDIAN),
                            mips.MIPS64(), mips.MIPS64(endian=Endianness.BIG_ENDIAN)]
            self["sparc"] = [sparc.SPARC(), sparc.SPARC64()]
        return

    def keys(self, full: bool = False) -> list[str]:
        archs = []
        for abi in self:
            if not full:
                archs.append(abi)
            else:
                for arch in self[abi]:
                    archs.append(arch.__class__.__name__.lower())
        return archs

    def find(self, name: str) -> Architecture:
        name = name.lower()
        for abi in self:
            for arch in self[abi]:
                if arch.__class__.__name__.lower() == name:
                    return arch
        raise KeyError(f"Cannot find architecture '{name}'")


Architectures = ArchitectureManager()


def is_x86_16(a: Architecture):
    return a.name == "Intel 8086 16bit"


def is_x86_32(a: Architecture):
    return a.name == "Intel i386 32bit"


def is_x86_64(a: Architecture):
    return a.name == "Intel i386 64bit"


def is_x86(a: Architecture):
    return is_x86_16(a) or is_x86_32(a) or is_x86_64(a)


def is_arm(a: Architecture):
    return a.name in ("ARM THUMB mode", "ARM Native mode")


def is_arm_thumb(a: Architecture):
    return a.name == "ARM THUMB mode"


def is_aarch64(a: Architecture):
    return a.name == "ARM AARCH64"


def is_mips(a: Architecture):
    return a.name == "MIPS 32bits"


def is_mips64(a: Architecture):
    return a.name == "MIPS 64bits"


def is_sparc(a: Architecture):
    return a.name == "SPARC 32bits"


def is_sparc64(a: Architecture):
    return a.name == "SPARC 64bits"


def is_ppc(a: Architecture):
    return a.name == "PowerPC 32bits"
