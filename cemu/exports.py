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
    MemoryLayoutEntryType,
)



def parse_as_lief_pe_permission(perm: str, extra: Any=None) -> int:
    res = 0
    p = MemoryPermission(perm)
    if p.r: res|=PE.SECTION_CHARACTERISTICS.MEM_READ
    if p.w: res|=PE.SECTION_CHARACTERISTICS.MEM_WRITE
    if p.x: res|=PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

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
        fd, outfile = tempfile.mkstemp(suffix=".exe", prefix="cemu-pe-amd64-")
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32_PLUS)
    else:
        fd, outfile = tempfile.mkstemp(suffix=".exe", prefix="cemu-pe-i386-")
        pe = PE.Binary(outfile, PE.PE_TYPE.PE32)

    os.close(fd)

    entrypoint = 0
    size_of_code = 0
    size_of_stack = 0
    size_of_idata = 0
    size_of_udata = 0

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
            size_of_code = size
        elif name == ".data":
            extra = "idata"
            sect.content = bytearray(b"\x00"*size)
            size_of_idata += size
        elif name == ".stack":
            extra = "udata"
            sect.content = bytearray(b"\x00"*size)
            size_of_stack = size
        else:
            extra = "udata"
            sect.content = bytearray(b"\x00"*size)
            size_of_udata += size

        sect.virtual_size = size
        sect.characteristics = parse_as_lief_pe_permission(permission, extra)
        pe.add_section(sect)

    # fixing pe header
    pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
    pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.DEBUG_STRIPPED)
    if is_x64:
        pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.LARGE_ADDRESS_AWARE)
    else:
        pe.header.add_characteristic(PE.HEADER_CHARACTERISTICS.CHARA_32BIT_MACHINE)

    # fixing pe optional header
    pe.optional_header.imagebase = 0x00400000
    pe.optional_header.baseof_code = entrypoint
    pe.optional_header.addressof_entrypoint = entrypoint
    pe.optional_header.major_operating_system_version = 0x04
    pe.optional_header.minor_operating_system_version = 0x00
    pe.optional_header.major_subsystem_version = 0x05
    pe.optional_header.minor_subsystem_version = 0x02
    pe.optional_header.major_linker_version = 0x02
    pe.optional_header.minor_linker_version = 0x1e
    pe.optional_header.sizeof_code = size_of_code
    pe.optional_header.sizeof_stack_commit = size_of_stack
    pe.optional_header.sizeof_uninitialized_data = size_of_udata
    pe.optional_header.sizeof_initialized_data = size_of_idata
    # pe.optional_header.subsystem = PE.SUBSYSTEM.WINDOWS_GUI
    pe.optional_header.remove(PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    pe.optional_header.remove(PE.DLL_CHARACTERISTICS.NX_COMPAT)
    pe.optional_header.add(PE.DLL_CHARACTERISTICS.NO_SEH)

    pe.add_library("kernel32.dll")
    pe.add_library("ntdll.dll")



    #building exe to disk
    builder = PE.Builder(pe)
    builder.build_imports(True)
    builder.build()
    builder.write(outfile)
    return outfile



def build_elf_executable(asm_code: bytearray, memory_layout: List[MemoryLayoutEntryType] , arch: Architecture) -> str:
    """
    """
    raise NotImplementedError("ELF generation will be implemented soon")

    bits = arch.ptrsize * 8

    if bits not in (32, 64):
        raise ValueError("Invalid architecture")

    outfile = "/tmp/cemu-elf-{}-{}b-{}".format(arch.name, bits, arch.endian_str)
    if bits == 32:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS32)
        elf.header.entrypoint = 0x00400000
    else:
        elf = ELF.Binary(outfile, ELF.ELF_CLASS.CLASS64)
        elf.header.entrypoint = 0x140000000


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