import os
import pathlib
import random
import string
from typing import Optional, Tuple

import capstone
import keystone
import unicorn
from PyQt6.QtWidgets import QTextEdit

import cemu.core
from cemu.arch import (Architecture, Architectures, Endianness, is_aarch64,
                       is_arm, is_arm_thumb, is_mips, is_mips64, is_sparc,
                       is_sparc64, is_x86_16, is_x86_32, is_x86_64)
from cemu.const import COMMENT_MARKER, PROPERTY_MARKER
from cemu.log import dbg

DISASSEMBLY_DEFAULT_BASE_ADDRESS = 0x40000


def hexdump(source: bytearray, length: int = 0x10, separator: str = ".", show_raw: bool = False, base: int = 0x00) -> str:
    """
    Produces a `hexdump` command like output version of the bytearray given.
    """
    result: list[str] = []
    for i in range(0, len(source), length):
        s = source[i:i+length]

        hexa = ' '.join(["%02X" % c for c in s])
        text = ''.join([chr(c) if 0x20 <= c < 0x7F else separator for c in s])

        if show_raw:
            result.append(hexa)
        else:
            result.append("%#-.*x   %-*s  %s" %
                          (16, base+i, 3*length, hexa, text))

    return '\n'.join(result)


def format_address(addr: int, arch: Architecture) -> str:
    if arch.ptrsize == 2:
        return f"{addr:#04x}"
    elif arch.ptrsize == 4:
        return f"{addr:#08x}"
    elif arch.ptrsize == 8:
        return f"{addr:#016x}"
    else:
        raise ValueError(f"Invalid value for '{arch.ptrsize=}'")


def get_arch_mode(lib: str) -> Tuple[int, int, int]:

    arch = cemu.core.context.architecture

    # x86
    if is_x86_16(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_X86, keystone.KS_MODE_16, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_16, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_X86, unicorn.UC_MODE_16, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    if is_x86_32(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_X86, keystone.KS_MODE_32, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_32, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    if is_x86_64(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_X86, keystone.KS_MODE_64, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_64, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    # arm
    if is_arm(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    if is_arm_thumb(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    # aarch64
    if is_aarch64(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_ARM64, 0, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    # mips/mips64
    if is_mips(arch):
        if arch.endianness == Endianness.LITTLE_ENDIAN:
            if lib == "keystone":
                return (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_LITTLE_ENDIAN)
            elif lib == "capstone":
                return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_LITTLE_ENDIAN)
            elif lib == "unicorn":
                return (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.UC_MODE_LITTLE_ENDIAN)
            else:
                raise ValueError(f"Unknown module '{lib}' for {arch}")
        else:
            if lib == "keystone":
                return (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_BIG_ENDIAN)
            elif lib == "capstone":
                return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_BIG_ENDIAN)
            elif lib == "unicorn":
                return (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.UC_MODE_BIG_ENDIAN)
            else:
                raise ValueError(f"Unknown module '{lib}' for {arch}")

    if is_mips64(arch):
        if arch.endianness == Endianness.LITTLE_ENDIAN:
            if lib == "keystone":
                return (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_LITTLE_ENDIAN)
            elif lib == "capstone":
                return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_LITTLE_ENDIAN)
            elif lib == "unicorn":
                return (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.UC_MODE_LITTLE_ENDIAN)
            else:
                raise ValueError(f"Unknown module '{lib}' for {arch}")
        else:
            if lib == "keystone":
                return (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_BIG_ENDIAN)
            elif lib == "capstone":
                return (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_BIG_ENDIAN)
            elif lib == "unicorn":
                return (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.UC_MODE_BIG_ENDIAN)
            else:
                raise ValueError(f"Unknown module '{lib}' for {arch}")

    # sparc/sparc64
    if is_sparc(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC32, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_SPARC, 0, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_SPARC, unicorn.UC_MODE_SPARC32, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")
    if is_sparc64(arch):
        if lib == "keystone":
            return (keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC64, keystone.KS_MODE_LITTLE_ENDIAN)
        elif lib == "capstone":
            return (capstone.CS_ARCH_SPARC, 0, capstone.CS_MODE_LITTLE_ENDIAN)
        elif lib == "unicorn":
            return (unicorn.UC_ARCH_SPARC, unicorn.UC_MODE_SPARC64, unicorn.UC_MODE_LITTLE_ENDIAN)
        else:
            raise ValueError(f"Unknown module '{lib}' for {arch}")

    # default, just throw
    raise ValueError(f"Unknown module '{lib}' for {arch}")


def disassemble(raw_data: bytes, count: int = -1, base: int = DISASSEMBLY_DEFAULT_BASE_ADDRESS) -> dict[int, Tuple[str, str]]:
    """Disassemble the code given as raw data, with the given architecture.

    Args:
        raw_data (bytes): the raw byte code to disassemble
        arch (Architecture): the architecture to use for disassembling
        count (int, optional): the maximum number of instruction to disassemble. Defaults to -1.
        count (int, optional): the disassembled code base address. Defaults to DISASSEMBLY_DEFAULT_BASE_ADDRESS

    Returns:
        str: the text representation of the disassembled code
    """
    cs_arch, cs_mode, cs_endian = get_arch_mode("capstone")
    cs = capstone.Cs(cs_arch, cs_mode | cs_endian)
    insns: dict[int, Tuple[str, str]] = {}
    for idx, ins in enumerate(cs.disasm(bytes(raw_data), base)):
        insns[ins.address] = (ins.mnemonic, ins.op_str)
        if idx == count:
            break

    return insns


def disassemble_file(fpath: pathlib.Path) -> dict[int, Tuple[str, str]]:
    with fpath.open('rb') as f:
        return disassemble(f.read())


def assemble(asm_code: str, as_bytes: bool = True) -> Tuple[bytes, int]:
    """
    Helper function to assemble code receive in parameter `asm_code` using Keystone.

    @param asm_code : assembly code in bytes (multiple instructions must be separated by ';')
    @param mode : defines the mode to use Keystone with
    @return a tuple of bytecodes as bytearray, along with the number of instruction compiled. If failed, the
    bytearray will be empty, the count of instruction will be the negative number for the faulty line.
    """
    arch = cemu.core.context.architecture
    ks_arch, ks_mode, ks_endian = get_arch_mode("keystone")
    ks = keystone.Ks(ks_arch, ks_mode | ks_endian)

    try:
        bytecode, cnt = ks.asm(asm_code, as_bytes=as_bytes)
        if not bytecode or not cnt:
            return (b'', 0)
        bytecode = bytes(bytecode)
    except keystone.keystone.KsError as kse:
        return (b'', kse.get_asm_count())

    return (bytecode, cnt)


def ishex(x: str) -> bool:
    if x.lower().startswith("0x"):
        x = x[2:]
    return all([c in string.hexdigits for c in x])


def get_cursor_row_number(widget: QTextEdit) -> int:
    """Get the cursor row number from the QTextEdit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        int: _description_
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return text[:pos].count(os.linesep)


def get_cursor_column_number(widget: QTextEdit) -> int:
    """Get the cursor column number from the QTextEdit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        int: _description_
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return len(text[:pos].split(os.linesep)[-1])


def get_cursor_position(widget: QTextEdit) -> Tuple[int, int]:
    """Returns the position of a cursor like (nb_row, nb_col) from a textedit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        Tuple[int, int]: _description_
    """
    return (get_cursor_row_number(widget), get_cursor_column_number(widget))


def generate_random_string(length: int) -> str:
    """Returns a random string

    Args:
        length (int): _description_

    Returns:
        str: _description_
    """
    charset = string.ascii_letters + string.digits
    return "".join(random.choice(charset) for _ in range(length))


def get_metadata_from_stream(content: str) -> Optional[Tuple[Architecture, Endianness]]:
    """Parse a file content to automatically extract metadata. Metadata can only be passed in the file
    header, and *must* be a commented line (i.e. starting with `;;; `) followed by the property marker (i.e. `@@@`).
    Both the architecture and endianess *must* be provided

    Example:
    ;;; @@@architecture x86_64
    ;;; @@@endianness little

    Args:
        content (str): _description_

    Returns:
        Optional[Tuple[str, str]]: _description_

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
