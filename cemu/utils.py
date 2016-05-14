# -*- coding: utf-8 -*-

from .arch import Architecture

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

def get_memory_alignment(mode):
    if mode == Architecture.X86_16_INTEL:
        return 16

    if mode in (Architecture.X86_64_INTEL, Architecture.X86_64_ATT):
        return 64

    return 32


def format_address(addr, mode):
    memalign_size = get_memory_alignment(mode)
    if memalign_size == 32:
        return "%#.8x" % (addr & 0xFFFFFFFF)
    elif memalign_size == 64:
        return "%#.16x" % (addr & 0xFFFFFFFFFFFFFFFF)
