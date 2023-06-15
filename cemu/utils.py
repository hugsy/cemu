import os
import pathlib
import random
import string
from dataclasses import dataclass
from typing import Optional

import keystone

import cemu.core
import cemu.errors
from cemu.arch import Architecture, Architectures, Endianness
from cemu.const import COMMENT_MARKER, PROPERTY_MARKER
from cemu.log import dbg

DISASSEMBLY_DEFAULT_BASE_ADDRESS = 0x40000


def hexdump(
    source: bytearray,
    alignment: int = 0x10,
    separator: str = ".",
    show_raw: bool = False,
    base: int = 0x00,
) -> str:
    """
    Produces a `hexdump` command like output version of the bytearray given.
    """
    result: list[str] = []
    for i in range(0, len(source), alignment):
        s = source[i : i + alignment]

        hexa = " ".join(["%02X" % c for c in s])
        text = "".join([chr(c) if 0x20 <= c < 0x7F else separator for c in s])

        if show_raw:
            result.append(hexa)
        else:
            result.append(
                "%#-.*x   %-*s  %s" % (16, base + i, 3 * alignment, hexa, text)
            )

    return os.linesep.join(result)


def format_address(addr: int, arch: Optional[Architecture] = None) -> str:
    if arch is None:
        arch = cemu.core.context.architecture

    if arch.ptrsize == 2:
        return f"{addr:#04x}"
    elif arch.ptrsize == 4:
        return f"{addr:#08x}"
    elif arch.ptrsize == 8:
        return f"{addr:#016x}"
    else:
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


def disassemble(
    raw_data: bytes, count: int = -1, base: int = DISASSEMBLY_DEFAULT_BASE_ADDRESS
) -> list[Instruction]:
    """Disassemble the code given as raw data, with the given architecture.

    Args:
        raw_data (bytes): the raw byte code to disassemble
        arch (Architecture): the architecture to use for disassembling
        count (int, optional): the maximum number of instruction to disassemble. Defaults to -1.
        count (int, optional): the disassembled code base address. Defaults to DISASSEMBLY_DEFAULT_BASE_ADDRESS

    Returns:
        str: the text representation of the disassembled code
    """
    arch = cemu.core.context.architecture
    insns: list[Instruction] = []
    for idx, ins in enumerate(arch.cs.disasm(raw_data, base)):
        insns.append(Instruction(ins.address, ins.mnemonic, ins.op_str, ins.bytes))
        if idx == count:
            break

    return insns


def disassemble_file(fpath: pathlib.Path) -> list[Instruction]:
    with fpath.open("rb") as f:
        return disassemble(f.read())


def assemble(
    code: str, base_address: int = DISASSEMBLY_DEFAULT_BASE_ADDRESS
) -> list[Instruction]:
    """
    Helper function to assemble code receive in parameter `asm_code` using Keystone.

    @param code : assembly code in bytes (multiple instructions must be separated by ';')
    @param base_address : (opt) the base address to use

    @return a tuple of bytecodes as bytearray, along with the number of instruction compiled. If failed, the
    bytearray will be empty, the count of instruction will be the negative number for the faulty line.
    """
    arch = cemu.core.context.architecture

    #
    # Compile the entire given code
    #
    try:
        bytecode, assembled_insn_count = arch.ks.asm(code, as_bytes=True)
        if not bytecode or assembled_insn_count == 0:
            raise cemu.errors.AssemblyException
    except keystone.keystone.KsError as kse:
        raise cemu.errors.AssemblyException(
            f"Keystone exception {str(kse)}, asm_count={kse.get_asm_count() or -1}"
        )

    #
    # Decompile it and return the stuff
    #
    disass_insns = disassemble(bytes(bytecode), base=base_address)
    assert len(disass_insns) == assembled_insn_count
    return disass_insns


def assemble_file(fpath: pathlib.Path) -> list[Instruction]:
    with fpath.open("r") as f:
        return assemble(f.read())


def ishex(x: str) -> bool:
    if x.lower().startswith("0x"):
        x = x[2:]
    return all([c in string.hexdigits for c in x])


def generate_random_string(length: int) -> str:
    """Returns a random string

    Args:
        length (int): _description_

    Returns:
        str: _description_
    """
    charset = string.ascii_letters + string.digits
    return "".join(random.choice(charset) for _ in range(length))


def get_metadata_from_stream(content: str) -> Optional[tuple[Architecture, Endianness]]:
    """Parse a file content to automatically extract metadata. Metadata can only be passed in the file
    header, and *must* be a commented line (i.e. starting with `;;; `) followed by the property marker (i.e. `@@@`).
    Both the architecture and endianess *must* be provided

    Example:
    ;;; @@@architecture x86_64
    ;;; @@@endianness little

    Args:
        content (str): _description_

    Returns:
        Optional[tuple[str, str]]: _description_

    Raises:
        KeyError:
            - if an architecture metadata is found, but invalid
            - if an endianess metadata is found, but invalid
    """
    arch: Optional[Architecture] = None
    endian: Optional[Endianness] = None

    for line in content.splitlines():
        part = line.strip().split()
        if len(part) < 4:
            return None

        if (part[0] != COMMENT_MARKER) and (arch and endian):
            return (arch, endian)

        if not part[1].startswith(PROPERTY_MARKER):
            continue

        metadata_type = part[1].lstrip(PROPERTY_MARKER).lower()
        metadata_value = part[2].lower()

        if metadata_type == "architecture" and not arch:
            arch = Architectures.find(metadata_value)
            dbg(f"Forcing architecture '{arch}'")
            continue

        if metadata_type == "endianness" and not endian:
            if metadata_value == "little":
                endian = Endianness.LITTLE_ENDIAN
            elif metadata_value == "big":
                endian = Endianness.BIG_ENDIAN
            else:
                continue
            dbg(f"Forcing endianness '{endian}'")

    return None
