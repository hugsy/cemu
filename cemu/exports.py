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


from .ui.mapping import (
    MemoryLayoutEntryType,
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


def build_pe_executable(asm_code: bytearray, memory_layout: List[MemoryLayoutEntryType] , arch: Architecture) -> str:
    """
    Uses LIEF to build a standalone binary.

    Upon success, return the path to the file generated
    """

    if not is_x86_32(arch) and not is_x86_64(arch):
        raise ValueError("Unsupported architecture for PE generation")

    is_x64 = is_x86_64(arch)

    if is_x64:
        fd, outfile = tempfile.mkstemp(suffix=".exe", prefix="cemu-pe-x64-")
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32_PLUS)
    else:
        fd, outfile = tempfile.mkstemp(suffix=".exe", prefix="cemu-pe-x86-")
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32)

    os.close(fd)

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
            sect.content = bytearray(b"\x00"*size)
        else:
            extra = "udata"
            sect.content = bytearray(b"\x00"*size)

        sect.size = size
        sect.characteristics = parse_as_lief_pe_permission(permission, extra)
        pe.add_section(sect)

    #fixing extra headers
    pe.header.characteristics_list.add(PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
    if not is_x64:
        pe.header.characteristics_list.add(PE.HEADER_CHARACTERISTICS.CHARA_32BIT_MACHINE)

    pe.optional_header.imagebase = 0x00400000
    pe.optional_header.addressof_entrypoint = entrypoint
    pe.optional_header.dll_characteristics &= ~PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    pe.optional_header.dll_characteristics &= ~PE.DLL_CHARACTERISTICS.NX_COMPAT
    pe.optional_header.dll_characteristics |= PE.DLL_CHARACTERISTICS.NO_SEH

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

    is_32b = (bits == 32)

    outfile = "/tmp/cemu-elf-{}-{}b-{}.out".format(arch.name, bits, arch.endian_str())
    raise NotImplementedError("soon")
    if is_32b:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS32)
    else:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS64)


    # set arch // dir(lief.ELF.ARCH)
    if is_x86_32(arch):
        elf.header.machine_type = ELF.ARCH.i386
    elif is_x86_64(arch):
        elf.header.machine_type = ELF.ARCH.x86_64
    elif is_arm(arch):
        elf.header.machine_type = ELF.ARCH.ARM
    elif is_aarch64(arch):
        elf.header.machine_type = ELF.ARCH.AARCH64
    elif is_mips(arch):
        elf.header.machine_type = ELF.ARCH.MIPS
    else:
        raise ValueError("Invalid architecture")


    # set extra headers
    if is_32b:
        elf.header.imagebase = 0x00400000
    else:
        elf.header.imagebase = 0x140000000


    # adding sections
    # "program header" segment
    s = ELF.Segment()
    s.flags = ELF.SEGMENT_FLAGS.R | ELF.SEGMENT_FLAGS.X
    s.type = ELF.SEGMENT_TYPES.PHDR
    elf.add(s)

    # "code" segment
    s = ELF.Segment()
    s.flags = ELF.SEGMENT_FLAGS.R | ELF.SEGMENT_FLAGS.X
    s.type = ELF.SEGMENT_TYPES.LOAD
    elf.add(s)

    # "data" segment
    s = ELF.Segment()
    s.flags = ELF.SEGMENT_FLAGS.R | ELF.SEGMENT_FLAGS.W
    s.type = ELF.SEGMENT_TYPES.LOAD
    elf.add(s)

    elf.header.entrypoint = elf.header.imagebase

    builder = ELF.Builder(elf)
    builder.build()
    builder.write(outfile)
    return outfile