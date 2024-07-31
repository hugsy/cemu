import os
import pathlib
import random
import string
from typing import Optional

from .arch import Instruction, Architecture, Architectures, Endianness
import cemu.core
import cemu.errors

from cemu.const import COMMENT_MARKER, PROPERTY_MARKER
from cemu.log import dbg

DISASSEMBLY_DEFAULT_BASE_ADDRESS = 0x40000


def hexdump(
    source: bytes,
    alignment: int = 0x10,
    separator: str = ".",
    show_raw: bool = False,
    base: int = 0x00,
) -> str:
    """Produces a `hexdump` command like output version of the bytearray given.

    Args:
        source (bytes): _description_
        alignment (int, optional): _description_. Defaults to 0x10.
        separator (str, optional): _description_. Defaults to ".".
        show_raw (bool, optional): _description_. Defaults to False.
        base (int, optional): _description_. Defaults to 0x00.

    Returns:
        str: _description_
    """
    result: list[str] = []
    for i in range(0, len(source), alignment):
        chunk = source[i : i + alignment]
        hexa = " ".join([f"{c:02X}" for c in chunk])
        text = "".join([chr(c) if 0x20 <= c < 0x7F else separator for c in chunk])

        if show_raw:
            result.append(hexa)
        else:
            result.append(f"{format_address(base)}  {hexa}  {text}")

    return os.linesep.join(result)


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


def get_metadata_from_stream(
    content: str,
) -> Optional[tuple[Architecture, Endianness]]:
    """Parse a file content to automatically extract metadata. Metadata can only be passed in the file
    header, and *must* be a commented line (i.e. starting with `;;; `) followed by the property marker (i.e. `@@@`).
    Both the architecture and endianess *must* be provided

    Example:
    ;;; @@@architecture x86_64
    ;;; @@@endianness little

    Args:
        content (str): _description_

    Returns:
        Optional[tuple[Architecture, Endianness]]: _description_

    Raises:
        KeyError:
            - if an architecture metadata is found, but invalid
            - if an endianess metadata is found, but invalid
    """
    arch: Optional[Architecture] = None
    endian: Optional[Endianness] = None

    for line in content.splitlines():
        # if already set, don't bother continuing
        if arch and endian:
            return (arch, endian)

        # validate the line format
        part = line.strip().split()
        if len(part) != 3:
            continue

        if part[0] != COMMENT_MARKER:
            continue

        if not part[1].startswith(PROPERTY_MARKER):
            continue

        metadata_type = part[1].lstrip(PROPERTY_MARKER).lower()
        metadata_value = part[2].lower()

        if metadata_type == "architecture" and not arch:
            arch = Architectures.find(metadata_value)
            dbg(f"Setting architecture from metadata to '{arch}'")
            continue

        if metadata_type == "endianness" and not endian:
            match metadata_value:
                case "little":
                    endian = Endianness.LITTLE_ENDIAN
                case "big":
                    endian = Endianness.BIG_ENDIAN
                case _:
                    raise ValueError
            dbg(f"Setting endianness from metadata to '{endian}'")

    return None