from dataclasses import dataclass
import enum
import importlib
import pathlib
from typing import Optional, TYPE_CHECKING

import capstone
import keystone
import unicorn

import cemu.errors
from cemu.const import SYSCALLS_PATH
from cemu.log import dbg
from cemu.utils import DISASSEMBLY_DEFAULT_BASE_ADDRESS
from ..ui.utils import popup, PopupType

if TYPE_CHECKING:
    import cemu.core


class Endianness(enum.Enum):
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __str__(self) -> str:
        return self.name.replace("_", " ").title()

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
            import cemu.core

            self.__context = cemu.core.context
            assert isinstance(self.__context, cemu.core.GlobalContext)

        if not self.__syscalls:
            syscall_dir = SYSCALLS_PATH / str(self.__context.os)

            try:
                fpath = syscall_dir / (self.syscall_filename + ".csv")
            except ValueError as e:
                popup(str(e), PopupType.Error, "No Syscall File Error")
                return {}

            self.__syscalls = {}
            if fpath.exists():
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
        return self.name == x.name and self.endianness == x.endianness and self.syntax == x.syntax

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


def format_address(addr: int, arch: Optional[Architecture] = None) -> str:
    """Format an address to string, aligned to the given architecture

    Args:
        addr (int): _description_
        arch (Optional[Architecture], optional): _description_. Defaults to None.

    Raises:
        ValueError: _description_

    Returns:
        str: _description_
    """
    if arch is None:
        import cemu.core

        arch = cemu.core.context.architecture

    match arch.ptrsize:
        case 2:
            return f"{addr:#04x}"
        case 4:
            return f"{addr:#08x}"
        case 8:
            return f"{addr:#016x}"
        case _:
            raise ValueError(f"Invalid value for '{arch.ptrsize=}'")


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str
    bytes: bytes

    @property
    def size(self):
        return len(self.bytes)

    @property
    def end(self) -> int:
        return self.address + self.size

    def __str__(self):
        return f'Instruction({self.address:#x}, "{self.mnemonic} {self.operands}")'


def disassemble(raw_data: bytes, count: int = -1, base: int = DISASSEMBLY_DEFAULT_BASE_ADDRESS) -> list[Instruction]:
    """Disassemble the code given as raw data, with the given architecture.

    Args:
        raw_data (bytes): the raw byte code to disassemble
        arch (Architecture): the architecture to use for disassembling
        count (int, optional): the maximum number of instruction to disassemble. Defaults to -1.
        base (int, optional): the disassembled code base address. Defaults to DISASSEMBLY_DEFAULT_BASE_ADDRESS

    Returns:
        str: the text representation of the disassembled code
    """
    arch = cemu.core.context.architecture
    insns: list[Instruction] = []
    for idx, ins in enumerate(arch.cs.disasm(raw_data, base)):
        insn = Instruction(ins.address, ins.mnemonic, ins.op_str, ins.bytes)
        insns.append(insn)
        if idx == count:
            break

    dbg(f"{insns=}")
    return insns


def disassemble_file(fpath: pathlib.Path) -> list[Instruction]:
    return disassemble(fpath.read_bytes())


def assemble(code: str, base_address: int = DISASSEMBLY_DEFAULT_BASE_ADDRESS) -> list[Instruction]:
    """
    Helper function to assemble code receive in parameter `asm_code` using Keystone.

    @param code : assembly code in bytes (multiple instructions must be separated by ';')
    @param base_address : (opt) the base address to use

    @return a list of Instruction
    """
    arch = cemu.core.context.architecture

    #
    # Compile the entire given code
    #
    bytecode, assembled_insn_count = arch.ks.asm(code, as_bytes=True, addr=base_address)
    if not bytecode or assembled_insn_count == 0:
        raise cemu.errors.AssemblyException("Not instruction compiled")

    assert isinstance(bytecode, bytes)

    #
    # Decompile it and return the stuff
    #
    insns = disassemble(bytecode, base=base_address)
    dbg(f"{insns=}")
    return insns


def assemble_file(fpath: pathlib.Path) -> list[Instruction]:
    return assemble(fpath.read_text())
