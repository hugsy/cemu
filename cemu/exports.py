from typing import Callable, Dict, List, Tuple, Any

from lief import (
    PE,
    ELF,
)

from .arch import (
    Architecture,
)


def parse_as_lief_pe_permission(perm: str, extra: Any=None) -> int:
    res = 0
    for p in perm.split("|"):
        p = p.strip()
        if p == "READ" or p == "ALL":
            res|=PE.SECTION_CHARACTERISTICS.MEM_READ
        if p == "WRITE" or p == "ALL":
            res|=PE.SECTION_CHARACTERISTICS.MEM_WRITE
        if p == "EXEC" or p == "ALL":
            res|=PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

    if extra:
        if extra.lower()=="code":
            res|=PE.SECTION_CHARACTERISTICS.CNT_CODE
        if extra.lower()=="idata":
            res|=PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
        if extra.lower()=="udata":
            res|=PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA

    return res


def build_pe_executable(asm_code: bytearray, memory_layout: List[Tuple[str, int, int, str, Any]] , arch: Architecture) -> str:
    """
    Uses LIEF to build a standalone binary.

    Upon success, return the path to the file generated
    """
    bits = arch.ptrsize * 8
    if bits not in (32, 64):
        raise ValueError("Invalid architecture")

    if bits == 64:
        outfile = "/tmp/cemu-pe-x64.exe"
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32_PLUS)
    else:
        outfile = "/tmp/cemu-pe-x86.exe"
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32)

    entrypoint = 0

    # adding sections
    for name, base_address, size, permission, _ in memory_layout:
        sect = PE.Section(name)
        sect.virtual_address = base_address
        if name == ".text":
            # .text section: copy our code and set the entrypoint to the
            # beginning VA
            extra = "code"
            sect.content = asm_code
            entrypoint = base_address
        elif name == ".data":
            extra = "idata"
            sect.content = b"\x00"*size
        else:
            sect.content = b"\x00"*size
            extra = "udata"
        sect.size = size
        sect.characteristics = parse_as_lief_pe_permission(permission, extra)
        pe.add_section(sect)

    #fixing extra headers
    pe.header.characteristics_list.add(PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
    if bits == 32:
        pe.header.characteristics_list.add(PE.HEADER_CHARACTERISTICS.CHARA_32BIT_MACHINE)
        pe.optional_header.imagebase = 0x00400000
    else:
        pe.optional_header.imagebase = 0x140000000
    pe.optional_header.addressof_entrypoint = entrypoint
    pe.optional_header.dll_characteristics &= ~PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    pe.optional_header.dll_characteristics &= ~PE.DLL_CHARACTERISTICS.NX_COMPAT

    #building exe to disk
    builder = PE.Builder(pe)
    builder.build_imports(True)
    builder.build()
    builder.write(outfile)
    return outfile



def build_elf_executable(asm_code: bytearray, memory_layout: List[Tuple[str, int, int, str, Any]] , arch: Architecture) -> str:
    """
    """
    bits = arch.ptrsize * 8

    if bits not in (32, 64):
        raise ValueError("Invalid architecture")

    outfile = "/tmp/cemu-elf.out"
    raise NotImplementedError("soon")
    if bits == 64:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS64)
    else:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS32)
    # set arch
    # set bitness
    builder = PE.Builder(elf)
    builder.build_imports(True)
    builder.build()
    builder.write(outfile)
    return outfile