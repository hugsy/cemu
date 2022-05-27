# -*- coding: utf-8 -*-

from cemu.arch.ppc import PowerPC
from cemu.arch.sparc import SPARC, SPARC64
from cemu.arch.mips import MIPS, MIPS64
from cemu.arch.arm import ARM, AARCH64
from cemu.arch.x86 import X86, X86_32, X86_64
import enum
import os
import csv
import abc

from cemu.const import SYSCALLS_PATH


class Endianness(enum.Enum):
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Syntax(enum.Enum):
    INTEL = 1
    ATT = 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class Architecture(object):
    """Generic metaclass for the architectures."""
    __metaclass__ = abc.ABCMeta

    endianness = Endianness.LITTLE_ENDIAN
    syntax = Syntax.INTEL
    __syscalls = None

    @abc.abstractproperty
    def name(self):
        pass

    @abc.abstractproperty
    def registers(self):
        pass

    @abc.abstractproperty
    def instruction_length(self):
        pass

    @abc.abstractproperty
    def flag(self):
        pass

    @abc.abstractproperty
    def pc(self):
        pass

    @abc.abstractproperty
    def sp(self):
        pass

    @abc.abstractproperty
    def ptrsize(self):
        pass

    @abc.abstractproperty
    def regsize(self):
        pass

    @abc.abstractproperty
    def syscall_filename(self) -> str:
        pass

    def __str__(self):
        return f"{self.name} (Ptrsize={self.ptrsize}, Endian={self.endianness}, Syntax={self.syntax})"

    syscall_base = 0

    @property
    def syscalls(self):
        if not self.__syscalls:
            fpath = SYSCALLS_PATH / self.syscall_filename
            self.__syscalls = {}

            with fpath.open('r') as fd:
                for row in fd.readlines():
                    row = [x.strip() for x in row.strip().split(',')]
                    syscall_number = int(row[0])
                    syscall_name = row[1].lower()
                    self.__syscalls[syscall_name] = self.syscall_base + \
                        syscall_number

        return self.__syscalls

    def __eq__(self, x):
        if not isinstance(x, Architecture):
            return False
        return self.name == x.name and self.endianness == x.endianness and self.syntax == x.syntax


Architectures = {
    "x86": [X86(), X86_32(), X86_64(),
            X86(syntax=Syntax.ATT), X86_32(syntax=Syntax.ATT), X86_64(syntax=Syntax.ATT)],
    "arm": [ARM(), ARM(thumb=True), AARCH64()],
    "mips": [MIPS(), MIPS(endian=Endianness.BIG_ENDIAN), MIPS64(), MIPS64(endian=Endianness.BIG_ENDIAN)],
    "sparc": [SPARC(), SPARC64()],
    # "ppc": [PowerPC()] # not supported by unicorn yet
}


def is_x86_16(a):
    return a.__class__.__name__ == "X86"


def is_x86_32(a):
    return a.__class__.__name__ == "X86_32"


def is_x86_64(a):
    return a.__class__.__name__ == "X86_64"


def is_x86(a):
    return is_x86_16(a) or is_x86_32(a) or is_x86_64(a)


def is_arm(a):
    return isinstance(a, ARM)


def is_arm_thumb(a):
    return is_arm(a) and a.thumb == True


def is_aarch64(a):
    return isinstance(a, AARCH64)


def is_mips(a):
    return isinstance(a, MIPS)


def is_mips64(a):
    return isinstance(a, MIPS64)


def is_sparc(a):
    return isinstance(a, SPARC)


def is_sparc64(a):
    return isinstance(a, SPARC64)


def is_ppc(a):
    return isinstance(a, PowerPC)


def get_all_architecture_names():
    archs = []
    for abi in Architectures:
        for arch in Architectures[abi]:
            archs.append(arch.__class__.__name__.lower())
    return archs


def get_architecture_by_name(name):
    for abi in Architectures:
        for arch in Architectures[abi]:
            if arch.__class__.__name__.lower() == name.lower():
                return arch
    raise KeyError("Cannot find architecture '{}'".format(name))
