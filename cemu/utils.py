# -*- coding: utf-8 -*-
import string

import capstone
import keystone
import unicorn

from cemu.arch import Syntax, \
    is_x86_16, is_x86_32, is_x86_64, is_x86, \
    is_arm, is_arm_thumb, is_aarch64, \
    is_mips, is_mips64, \
    is_sparc, is_sparc64, \
    is_ppc


def hexdump(source, length=0x10, separator='.', show_raw=False, base=0x00):
    result = []
    for i in range(0, len(source), length):
        s = source[i:i+length]

        hexa = ' '.join(["%02X" % c for c in s])
        text = ''.join( [chr(c) if 0x20 <= c < 0x7F else separator for c in s] )

        if show_raw:
            result.append(hexa)
        else:
            result.append( "%#-.*x   %-*s  %s" % (16, base+i, 3*length, hexa, text) )

    return '\n'.join(result)



def format_address(addr, mode):
    if mode.ptrsize == 2:
        return "%#.4x" % (addr & 0xFFFF)
    elif mode.ptrsize == 4:
        return "%#.8x" % (addr & 0xFFFFFFFF)
    elif mode.ptrsize == 8:
        return "%#.16x" % (addr & 0xFFFFFFFFFFFFFFFF)


def get_arch_mode(lib, a):
    arch = mode = endian = None

    # x86
    if is_x86_16(a):
        if lib=="keystone":      arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_16, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":    arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_16, capstone.CS_MODE_LITTLE_ENDIAN
        else:                    arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_16, unicorn.UC_MODE_LITTLE_ENDIAN

    elif is_x86_32(a):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_32, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_32, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, unicorn.UC_MODE_LITTLE_ENDIAN

    elif is_x86_32(a):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_64, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_64, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, unicorn.UC_MODE_LITTLE_ENDIAN

    # arm
    elif is_arm(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM, unicorn.UC_MODE_LITTLE_ENDIAN
    elif is_arm_thumb(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB, unicorn.UC_MODE_LITTLE_ENDIAN

    # aarch64
    elif is_aarch64(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM64, 0, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, unicorn.UC_MODE_LITTLE_ENDIAN

    # powerpc (uncomment when unicorn supports ppc)
    # elif is_ppc(m):
    #     if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_PPC, keystone.KS_MODE_PPC32, keystone.KS_MODE_BIG_ENDIAN
    #     elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_PPC, 0, capstone.CS_MODE_BIG_ENDIAN
    #     else:                   arch, mode, endian = unicorn.UC_ARCH_PPC, unicorn.UC_MODE_PPC32, unicorn.UC_MODE_BIG_ENDIAN

    # mips/mips64
    elif is_mips(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.UC_MODE_LITTLE_ENDIAN
    elif is_mips(m) and m.endianness==Endianness.BIG:
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_BIG_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_BIG_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.UC_MODE_BIG_ENDIAN
    elif is_mips64(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.UC_MODE_LITTLE_ENDIAN
    elif is_mips64(m) and m.endianness==Endianness.BIG:
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_BIG_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_BIG_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.UC_MODE_BIG_ENDIAN

    # sparc/sparc64
    elif is_sparc(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC32, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_SPARC, 0, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_SPARC, unicorn.UC_MODE_SPARC32, unicorn.UC_MODE_LITTLE_ENDIAN
    elif is_sparc(m):
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC64, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_SPARC, 0, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   arch, mode, endian = unicorn.UC_ARCH_SPARC, unicorn.UC_MODE_SPARC64, unicorn.UC_MODE_LITTLE_ENDIAN

    if arch is None and mode is None and endian is None:
        raise Exception("Failed to get architecture parameter from mode")

    return arch, mode, endian


def disassemble(raw_data, mode):
    arch, mode, endian = get_arch_mode("capstone", mode)
    cs = capstone.Cs(arch, mode | endian)
    if is_x86(mode) and mode.syntax == Syntax.ATT:
        cs.syntax = capstone.CS_OPT_SYNTAX_ATT

    insns = ["{:s} {:s}".format(i.mnemonic, i.op_str) for i in cs.disasm(bytes(raw_data), 0x4000)]
    return "\n".join(insns)


def disassemble_file(fpath, mode):
    with open(fpath, 'rb') as f:
        raw_data = f.read()

    return disassemble(raw_data, mode)


def assemble(asm_code, mode):
    arch, mode, endian = get_arch_mode("keystone", mode)
    ks = keystone.Ks(arch, mode | endian)
    if is_x86(mode) and mode.syntax == Syntax.ATT:
        ks.syntax = keystone.KS_OPT_SYNTAX_ATT

    try:
        code, cnt = ks.asm(asm_code)
        if cnt==0:
            code = b""
        code = bytes(bytearray(code))
    except keystone.keystone.KsError:
        code, cnt = (b"", -1)

    return (code, cnt)


def ishex(x):
    if x.startswith("0x") or x.startswith("0X"):
        x = x[2:]
    return all([c in string.hexdigits for c in x])
