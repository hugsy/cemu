import tempfile
import pathlib
from typing import Any, List

from lief import PE  # type: ignore

from .arch import Architecture, is_x86_32, is_x86_64
from .memory import MemoryPermission, MemorySection
import cemu.utils


def parse_as_lief_pe_permission(perm: MemoryPermission, extra: Any = None) -> int:
    res = 0
    if perm.r:
        res |= PE.Section.CHARACTERISTICS.MEM_READ.value
    if perm.w:
        res |= PE.Section.CHARACTERISTICS.MEM_WRITE.value
    if perm.x:
        res |= PE.Section.CHARACTERISTICS.MEM_EXECUTE.value

    if extra:
        match extra.lower():
            case "code":
                res |= PE.Section.CHARACTERISTICS.CNT_CODE.value
            case "idata":
                res |= PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA.value
            case "udata":
                res |= PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA.value

    return res


def build_pe_executable(text: bytes, memory_layout: List[MemorySection], arch: Architecture) -> pathlib.Path:
    """
    Uses LIEF to build a standalone binary.

    Upon success, return the path to the file generated
    """

    if not is_x86_32(arch) and not is_x86_64(arch):
        raise ValueError("Unsupported architecture for PE generation")

    is_x64 = is_x86_64(arch)

    if is_x64:
        basename = "cemu-pe-amd64-{:s}".format(cemu.utils.generate_random_string(5))
        pe = PE.Binary(PE.PE_TYPE.PE32_PLUS)
    else:
        basename = "cemu-pe-i386-{:s}".format(cemu.utils.generate_random_string(5))
        pe = PE.Binary(PE.PE_TYPE.PE32)

    # adding sections
    sections = {}
    reladdr = 0x1000

    for mem in memory_layout:
        name, _, size, permission = (
            mem.name,
            mem.address,
            mem.size,
            mem.permission,
        )
        if name in (".stack",):
            continue

        sect = PE.Section(name)

        if name == ".text":
            # .text section: copy our code and set the entrypoint to the
            # beginning VA
            sect.content = memoryview(text)
            sect.virtual_address = reladdr
            sect.characteristics = parse_as_lief_pe_permission(permission, "code")
            sections["text"] = pe.add_section(sect, PE.SECTION_TYPES.TEXT)

        elif name == ".data":
            # .data is also sure to exist
            sect.content = memoryview(b"\x00")
            sect.virtual_address = reladdr
            sect.characteristics = parse_as_lief_pe_permission(permission, "udata")
            sections["data"] = pe.add_section(sect, PE.SECTION_TYPES.DATA)

        reladdr += size

    # fixing pe header
    pe.header.add_characteristic(PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE)
    pe.header.add_characteristic(PE.Header.CHARACTERISTICS.DEBUG_STRIPPED)
    if is_x64:
        pe.header.add_characteristic(PE.Header.CHARACTERISTICS.LARGE_ADDRESS_AWARE)
    else:
        pe.header.add_characteristic(PE.Header.CHARACTERISTICS.NEED_32BIT_MACHINE)

    # fixing pe optional header
    pe.optional_header.addressof_entrypoint = sections["text"].virtual_address
    pe.optional_header.major_operating_system_version = 0x04
    pe.optional_header.minor_operating_system_version = 0x00
    pe.optional_header.major_subsystem_version = 0x05
    pe.optional_header.minor_subsystem_version = 0x02
    pe.optional_header.major_linker_version = 0x02
    pe.optional_header.minor_linker_version = 0x1E
    pe.optional_header.remove(PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT)
    pe.optional_header.add(PE.OptionalHeader.DLL_CHARACTERISTICS.NO_SEH)
    # pe.add_library("ntdll.dll")

    # building exe to disk
    outfile = pathlib.Path(tempfile.gettempdir()) / f"{basename:s}.exe"
    builder = PE.Builder(pe)
    builder.build_imports(True)
    builder.build()
    builder.write(str(outfile.absolute()))
    assert outfile.exists()
    return outfile


def build_elf_executable(asm_code: bytes, memory_layout: List[MemorySection], arch: Architecture) -> str:
    """ """
    raise NotImplementedError("ELF generation will be implemented soon")
