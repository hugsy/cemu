from dataclasses import dataclass
from enum import IntFlag

import capstone
import keystone
import unicorn

from cemu.arch import Architecture, Endianness, Syntax


class X86(Architecture):
    name: str = "Intel 8086 16bit"
    pc: str = "IP"
    sp: str = "SP"
    flag: str = "EFLAGS"
    registers: list[str] = [
        pc,
        sp,
        "AX",
        "BX",
        "CX",
        "DX",
        "SI",
        "DI",
        "BP",
        flag,
    ]
    ptrsize: int = 2
    syscall_filename: str = "x86"

    def __init__(self, *args, **kwargs):
        self.endianness = kwargs.get("endian", Endianness.LITTLE_ENDIAN)
        self.syntax = kwargs.get("syntax", Syntax.INTEL)
        return

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_16,
            unicorn.UC_MODE_LITTLE_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_16,
            capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_X86,
            keystone.KS_MODE_16,
            keystone.KS_MODE_LITTLE_ENDIAN,
        )

    def uc_register(self, name: str) -> int:
        return getattr(unicorn.x86_const, f"UC_X86_REG_{name.upper()}")


class X86_32(X86):
    # See SDM VOL3a
    class SegmentType(IntFlag):
        Read = 0
        Data = 0
        Execute = 8
        Code = 8
        Accessed = 1
        ReadWrite = 2
        ExpandDown = 4

    @dataclass
    class SegmentDescriptor:
        base: int
        type: "X86_32.SegmentType"
        S: bool
        DPL: int
        P: bool

        def __int__(self) -> int:
            return (
                (self.base)
                | (self.type << 8)
                | (int(self.S) << 12)
                | (self.DPL << 13)
                | (int(self.P) << 15)
            )

    name = "Intel i386 32bit"
    pc = "EIP"
    sp = "ESP"
    selector_registers = [
        "CS",
        "DS",
        "ES",
        "FS",
        "GS",
        "SS",
    ]
    registers = [
        pc,
        sp,
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "ESI",
        "EDI",
        "EBP",  # GPR
        X86.flag,
    ] + selector_registers
    ptrsize = 4

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_32,
            unicorn.UC_MODE_LITTLE_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_32,
            capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_X86,
            keystone.KS_MODE_32,
            keystone.KS_MODE_LITTLE_ENDIAN,
        )


class X86_64(X86_32):
    name = "Intel i386 64bit"
    pc = "RIP"
    sp = "RSP"
    registers = [
        pc,
        sp,
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RSI",
        "RDI",
        "RBP",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
        X86_32.flag,
    ] + X86_32.selector_registers
    ptrsize = 8
    syscall_filename = "x86-64"
    syscall_filename = "x86-64"

    def unicorn(self) -> tuple[int, int, int]:
        return (
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_64,
            unicorn.UC_MODE_LITTLE_ENDIAN,
        )

    def capstone(self) -> tuple[int, int, int]:
        return (
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_64,
            capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def keystone(self) -> tuple[int, int, int]:
        return (
            keystone.KS_ARCH_X86,
            keystone.KS_MODE_64,
            keystone.KS_MODE_LITTLE_ENDIAN,
        )
