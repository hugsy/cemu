import os

import random
import string
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import cemu.arch

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
    import cemu.arch

    if not isinstance(source, bytes):
        raise ValueError("source must be of type `bytes`")

    if len(separator) != 1:
        raise ValueError("separator must be a single character")

    if (alignment & 1) == 1:
        raise ValueError("alignment must be a multiple of two")

    result: list[str] = []
    for i in range(0, len(source), alignment):
        chunk = source[i : i + alignment]
        hexa = " ".join([f"{c:02X}" for c in chunk])
        text = "".join([chr(c) if 0x20 <= c < 0x7F else separator for c in chunk])

        if show_raw:
            result.append(hexa)
        else:
            result.append(f"{cemu.arch.format_address(base+i)}  {hexa}  {text}")

    return os.linesep.join(result)


def ishex(x: str) -> bool:
    if x.lower().startswith("0x"):
        x = x[2:]
    return all([c in string.hexdigits for c in x])


def generate_random_string(length: int, charset: str = string.ascii_letters + string.digits) -> str:
    """Returns a random string

    Args:
        length (int): _description_

    Returns:
        str: _description_
    """
    if length < 1:
        raise ValueError("invalid length")

    return "".join(random.choice(charset) for _ in range(length))


def get_metadata_from_stream(
    content: str,
) -> Optional[tuple["cemu.arch.Architecture", "cemu.arch.Endianness"]]:
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
    import cemu.arch

    arch: Optional["cemu.arch.Architecture"] = None
    endian: Optional["cemu.arch.Endianness"] = None

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
            arch = cemu.arch.Architectures.find(metadata_value)
            dbg(f"Setting architecture from metadata to '{arch}'")
            continue

        if metadata_type == "endianness" and not endian:
            match metadata_value:
                case "little":
                    endian = cemu.arch.Endianness.LITTLE_ENDIAN
                case "big":
                    endian = cemu.arch.Endianness.BIG_ENDIAN
                case _:
                    raise ValueError
            dbg(f"Setting endianness from metadata to '{endian}'")

    return None
