# -*- coding: utf-8 -*-

import enum
import os
import csv
import abc

Endianness = enum.Enum("Endianness", "BIG LITTLE")
Syntax = enum.Enum("Syntaxes", "INTEL ATT")

class Architecture(object):
    """Generic metaclass for the architectures."""
    __metaclass__ = abc.ABCMeta

    endianness = Endianness.LITTLE

    @abc.abstractproperty
    def name(self):                       pass
    @abc.abstractproperty
    def registers(self):                  pass
    @abc.abstractproperty
    def instruction_length(self):         pass
    @abc.abstractproperty
    def flag(self):                       pass
    @abc.abstractproperty
    def pc(self):                         pass
    @abc.abstractproperty
    def sp(self):                         pass
    @abc.abstractproperty
    def ptrsize(self):                    pass
    @abc.abstractproperty
    def syscall_filename(self):           pass
    @property
    def endian_str(self):                 return "big" if self.is_big_endian() else "little"

    def is_big_endian(self):              return self.endianness == Endianness.BIG

    def __str__(self):                    return self.name

    @property
    def syscalls(self):
        path = os.path.dirname(os.path.realpath(__file__)) + "/../syscalls"
        fpath = "{}/{}.csv".format(path, self.syscall_filename)
        syscalls = {}

        with open(fpath, 'r') as fd:
            reader = csv.reader(fd, delimiter=',')
            for row in reader:
                syscall_number, syscall_name = int(row[0]), row[1].lower().strip().encode()
                syscalls[syscall_name] = syscall_number

        return syscalls


from cemu.arch.x86 import X86, X86_32, X86_64
from cemu.arch.arm import ARM, AARCH64
from cemu.arch.mips import MIPS, MIPS64
from cemu.arch.sparc import SPARC, SPARC64
from cemu.arch.ppc import PowerPC

Architectures = {
    "x86": [X86(), X86_32(), X86_64(), X86(syntax=Syntax.ATT), X86_32(syntax=Syntax.ATT), X86_64(syntax=Syntax.ATT), ],
    "arm": [ARM(), ARM(thumb=True), AARCH64()],
    "mips": [MIPS(), MIPS(endian=Endianness.BIG), MIPS64(), MIPS64(endian=Endianness.BIG),],
    "sparc": [SPARC(), SPARC64()],
    # "ppc": [PowerPC()] # not supported by unicorn yet
}

DEFAULT_ARCHITECTURE = Architectures["x86"][1] # x86-32

def is_x86_16(a): return isinstance(a, X86)
def is_x86_32(a): return isinstance(a, X86_32)
def is_x86_64(a): return isinstance(a, X86_64)
def is_x86(a): return is_x86_16(a) or is_x86_32(a) or is_x86_64(a)
def is_arm(a): return isinstance(a, ARM)
def is_arm_thumb(a): return is_arm(a) and a.thumb==True
def is_aarch64(a): return isinstance(a, AARCH64)
def is_mips(a): return isinstance(a, MIPS)
def is_mips64(a): return isinstance(a, MIPS64)
def is_sparc(a): return isinstance(a, SPARC)
def is_sparc64(a): return isinstance(a, SPARC64)
def is_ppc(a): return isinstance(a, PowerPC)
