import enum
import importlib
from typing import Optional, TYPE_CHECKING

import capstone
import keystone
import unicorn

from cemu.const import SYSCALLS_PATH

if TYPE_CHECKING:
    import cemu.core


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
        return self.name

    __context: Optional["cemu.core.GlobalContext"] = None
    __syscalls: Optional[dict[str, int]] = None
    syscall_base = 0

    @property
    def syscalls(self):
        if not self.__context:
            mod = __import__("cemu.core")
            self.__context = getattr(mod, "context")
            assert isinstance(self.__context, cemu.core.GlobalContext)

        if not self.__syscalls:
            syscall_dir = SYSCALLS_PATH / cemu.core.context.os
            fpath = syscall_dir / (self.syscall_filename + ".csv")
            self.__syscalls = {}

            with fpath.open("r") as fd:
                for row in fd.readlines():
                    row = [x.strip() for x in row.strip().split(",")]
                    syscall_number = int(row[0])
                    syscall_name = row[1].lower()
                    self.__syscalls[syscall_name] = self.syscall_base + syscall_number

        return self.__syscalls

    def __eq__(self, x):
        if not isinstance(x, Architecture):
            return False
        return (
            self.name == x.name
            and self.endianness == x.endianness
            and self.syntax == x.syntax
        )

    def unicorn(self) -> tuple[int, int, int]:
        """Returns a tuple with the values of unicorn architecture, mode, endianess

        Raises:
            KeyError: _description_

        Returns:
            tuple[int, int, int]: _description_
        """
        raise NotImplementedError

    @property
    def uc(self) -> "unicorn.Uc":
        arch, mode, endian = self.unicorn()
        return unicorn.Uc(arch, mode | endian)

    def uc_register(self, name: str) -> int:
        raise NotImplementedError

    def capstone(self) -> tuple[int, int, int]:
        """Returns a tuple with the values of unicorn architecture, mode, endianess

        Raises:
            KeyError: _description_

        Returns:
            tuple[int, int, int]: _description_
        """
        raise NotImplementedError

    @property
    def cs(self) -> "capstone.Cs":
        cs_arch, cs_mode, cs_endian = self.capstone()
        return capstone.Cs(cs_arch, cs_mode | cs_endian)

    def keystone(self) -> tuple[int, int, int]:
        """Returns a tuple with the values of unicorn architecture, mode, endianess

        Raises:
            KeyError: _description_

        Returns:
            tuple[int, int, int]: _description_
        """
        raise NotImplementedError

    @property
    def ks(self) -> "keystone.Ks":
        ks_arch, ks_mode, ks_endian = self.keystone()
        return keystone.Ks(ks_arch, ks_mode | ks_endian)


class ArchitectureManager(dict[str, list[Architecture]]):
    def __init__(self):
        super().__init__()
        self.load(True)

    def load(self, force_reload: bool = False) -> None:
        """Instanciate all the architecture objects"""
        if force_reload:
            generic = importlib.import_module(".generic", package="cemu.arch")
            x86 = importlib.import_module(".x86", package="cemu.arch")
            arm = importlib.import_module(".arm", package="cemu.arch")
            mips = importlib.import_module(".mips", package="cemu.arch")
            sparc = importlib.import_module(".sparc", package="cemu.arch")

            self["generic"] = [
                generic.Generic(),
            ]
            self["x86"] = [
                x86.X86(),
                x86.X86_32(),
                x86.X86_64(),
                x86.X86(syntax=Syntax.ATT),
                x86.X86_32(syntax=Syntax.ATT),
                x86.X86_64(syntax=Syntax.ATT),
            ]
            self["arm"] = [arm.ARM(), arm.ARM(thumb=True), arm.AARCH64()]
            self["mips"] = [
                mips.MIPS(),
                mips.MIPS(endian=Endianness.BIG_ENDIAN),
                mips.MIPS64(),
                mips.MIPS64(endian=Endianness.BIG_ENDIAN),
            ]
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

from .x86 import X86, X86_32, X86_64  # noqa: E402
from .arm import ARM, AARCH64  # noqa: E402
from .mips import MIPS, MIPS64  # noqa: E402
from .sparc import SPARC, SPARC64  # noqa: E402
from .ppc import PowerPC  # noqa: E402


def is_x86_16(a: Architecture):
    return isinstance(a, X86)


def is_x86_32(a: Architecture):
    return isinstance(a, X86_32)


def is_x86_64(a: Architecture):
    return isinstance(a, X86_64)


def is_x86(a: Architecture):
    return is_x86_16(a) or is_x86_32(a) or is_x86_64(a)


def is_arm(a: Architecture):
    return isinstance(a, ARM)


def is_arm_native(a: Architecture):
    return isinstance(a, ARM) and a.thumb is False  # type: ignore


def is_arm_thumb(a: Architecture):
    return isinstance(a, ARM) and a.thumb is True  # type: ignore


def is_aarch64(a: Architecture):
    return isinstance(a, AARCH64)


def is_mips(a: Architecture):
    return isinstance(a, MIPS)


def is_mips64(a: Architecture):
    return isinstance(a, MIPS64)


def is_sparc(a: Architecture):
    return isinstance(a, SPARC)


def is_sparc64(a: Architecture):
    return isinstance(a, SPARC64)


def is_ppc(a: Architecture):
    return isinstance(a, PowerPC)
