import tempfile, os

from typing import Callable, Dict, List, Tuple, Any

from lief import (
    PE,
    ELF,
)

from .arch import (
    Architecture,
    is_x86_32,
    is_x86_64,
    is_arm,
    is_aarch64,
    is_mips,
)


from .memory import (
    MemoryPermission,
    MemorySection,
)


from .utils import (
    generate_random_string,
)



def parse_as_lief_pe_permission(perm: MemoryPermission, extra: Any=None) -> int:
    res = 0
    if perm.r: res|=PE.SECTION_CHARACTERISTICS.MEM_READ
    if perm.w: res|=PE.SECTION_CHARACTERISTICS.MEM_WRITE
    if perm.x: res|=PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

    if extra:
        if extra.lower()=="code":
            res|=PE.SECTION_CHARACTERISTICS.CNT_CODE
        if extra.lower()=="idata":
            res|=PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
        if extra.lower()=="udata":
            res|=PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA

    return res


def build_pe_executable(asm_code: bytearray, memory_layout: List[MemorySection] , arch: Architecture) -> str:
    """
    Uses LIEF to build a standalone binary.

    Upon success, return the path to the file generated
    """

    if not is_x86_32(arch) and not is_x86_64(arch):
        raise ValueError("Unsupported architecture for PE generation")

    is_x64 = is_x86_64(arch)

    if is_x64:
        basename = "cemu-pe-amd64-{:s}".format(generate_random_string(5))
        pe = PE.Binary(basename, PE.PE_TYPE.PE32_PLUS)
    else:
        basename = "cemu-pe-i386-{:s}".format(generate_random_string(5))
        pe = PE.Binary(basename, PE.PE_TYPE.PE32)


    # adding sections
    sections = {}
    reladdr = 0x1000

    for mem in memory_layout:
        name, base_address, size, permission = mem.name, mem.address, mem.size, mem.permission
        if name in (".stack", ):
            continue

        sect = PE.Section(name)

        if name == ".text":
            # .text section: copy our code and set the entrypoint to the
            # beginning VA
            sect.content = asm_code
            sect.virtual_address = reladdr
            sect.characteristics = parse_as_lief_pe_permission(permission, "code")
            sections["text"] = pe.add_section(sect, PE.SECTION_TYPES.TEXT)

        elif name == ".data":
            # .data is also sure to exist
            sect.content = b"\x00"
            sect.virtual_address = reladdr
            sect.characteristics = parse_as_lief_pe_permission(permission, "udata")
            sections["data"] = pe.add_section(sect, PE.SECTION_TYPES.DATA)

        reladdr += size

    # fixing pe header
    pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
    pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.DEBUG_STRIPPED)
    if is_x64:
        pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.LARGE_ADDRESS_AWARE)
    else:
        pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.CHARA_32BIT_MACHINE)

    # fixing pe optional header
    pe.optional_header.addressof_entrypoint = sections["text"].virtual_address
    pe.optional_header.major_operating_system_version = 0x04
    pe.optional_header.minor_operating_system_version = 0x00
    pe.optional_header.major_subsystem_version = 0x05
    pe.optional_header.minor_subsystem_version = 0x02
    pe.optional_header.major_linker_version = 0x02
    pe.optional_header.minor_linker_version = 0x1e
    pe.optional_header.remove(PE.DLL_CHARACTERISTICS.NX_COMPAT)
    pe.optional_header.add(PE.DLL_CHARACTERISTICS.NO_SEH)
    # pe.add_library("ntdll.dll")

    #building exe to disk
    outfile = f"{tempfile.gettempdir()}{os.path.sep:s}{basename:s}.exe"
    builder = PE.Builder(pe)
    builder.build_imports(True)
    builder.build()
    builder.write(outfile)
    return outfile



def build_elf_executable(asm_code: bytearray, memory_layout: List[MemorySection] , arch: Architecture) -> str:
    """
    """
    raise NotImplementedError("ELF generation will be implemented soon")

