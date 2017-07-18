# -*- coding: utf-8 -*-

import enum
import os
import csv

Endianness = enum.Enum("Endianness",
                       "BIG LITTLE")

Architecture = enum.Enum('Architecture',
                         "X86_16_INTEL " + \
                         "X86_32_INTEL " + \
                         "X86_64_INTEL " + \
                         "X86_16_ATT " + \
                         "X86_32_ATT " + \
                         "X86_64_ATT " + \
                         "ARM_LE " + \
                         "ARM_BE " + \
                         "ARM_THUMB_LE " + \
                         "ARM_THUMB_BE " + \
                         "ARM_AARCH64 " + \
                         "MIPS " + \
                         "MIPS_BE " + \
                         "MIPS64 " + \
                         "MIPS64_BE " + \
                         "PPC " + \
                         "PPC64 " + \
                         "SPARC " + \
                         "SPARC_BE " + \
                         "SPARC64 " + \
                         "SPARC64_BE" )

X86_GPR = ["AX", "BX", "CX", "DX", "SI", "DI", "IP", "BP", "SP"]
X86_PGR = ["CS", "DS", "ES", "FS", "GS", "SS"]
X86_FLAG = ["EFLAGS", ]
X86_16_REGS = X86_GPR
X86_32_REGS = ["E"+x for x in X86_GPR] + X86_FLAG
X86_64_REGS = ["R"+x for x in X86_GPR] + ["R%d"%i for i in range(8,16)] + X86_FLAG

# http://www.keil.com/support/man/docs/armasm/armasm_dom1359731128950.htm
ARM_GPR = ["R%d"%i for i in range(11)] + ["R12",]
ARM_FLAG = ["CPSR", ]
ARM_REGS = ARM_GPR + ["FP", "SP", "LR", "PC",] + ARM_FLAG

AARCH64_GPR = ["X%d"%i for i in range(31)]
AARCH64_FLAG = ["NZCV", ] # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0801a/BABIBIGB.html
AARCH64_REGS = AARCH64_GPR + ["PC",] + AARCH64_FLAG

# https://msdn.microsoft.com/en-us/library/ms253512(v=vs.90).aspx
MIPS_GPR = ["ZERO", "AT", "V0", "V1" ] + \
           ["A%d"%i for i in range(4)] + \
           ["S%d"%i for i in range(9)]  + \
           ["T%d"%i for i in range(10)] + \
           ["K0", "K1"] + ["HI", "LO"]
MIPS_REGS = MIPS_GPR + ["GP", "SP", "RA", "PC"]

PPC_GPR = ["R%d"%i for i in range(32)]
PPC_REGS = PPC_GPR + ["PC", ]

SPARC_GPR = ["G%d"%i for i in range(8)] + ["L%d"%i for i in range(8)] + ["I%d"%i for i in range(8)] + ["O%d"%i for i in range(8)]
SPARC_FLAG = ["ICC", ] # incomplete https://www.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/include/asm-sparc/psr.h
SPARC_REGS = SPARC_GPR + ["PC", ] + SPARC_FLAG

modes = {"x86":[ (Architecture.X86_16_INTEL, "16bit, Intel syntax", X86_16_REGS, "IP", "SP", Endianness.LITTLE),
                 (Architecture.X86_32_INTEL, "32bit, Intel syntax", X86_32_REGS, "EIP", "ESP", Endianness.LITTLE),
                 (Architecture.X86_64_INTEL, "64bit, Intel syntax", X86_64_REGS, "RIP", "RSP", Endianness.LITTLE),
                 (Architecture.X86_16_ATT, "16bit, AT&T syntax", X86_16_REGS, "IP", "SP", Endianness.LITTLE),
                 (Architecture.X86_32_ATT, "32bit, AT&T syntax", X86_32_REGS, "EIP", "ESP", Endianness.LITTLE),
                 (Architecture.X86_64_ATT, "64bit, AT&T syntax", X86_64_REGS, "RIP", "RSP", Endianness.LITTLE), ],

         "arm":[ (Architecture.ARM_LE, "ARM - little endian", ARM_REGS, "PC", "SP", Endianness.LITTLE),
                 (Architecture.ARM_BE, "ARM - big endian", ARM_REGS, "PC", "SP", Endianness.BIG),
                 (Architecture.ARM_THUMB_LE, "ARM Thumb mode - little endian", ARM_REGS, "PC", "SP", Endianness.LITTLE),
                 (Architecture.ARM_THUMB_BE, "ARM Thumb mobe - big endian", ARM_REGS, "PC", "SP", Endianness.BIG),
                 (Architecture.ARM_AARCH64, "ARMv8 AARCH64", AARCH64_REGS, "PC", "SP", Endianness.LITTLE), ],

         "mips":[ (Architecture.MIPS, "MIPS - little endian", MIPS_REGS, "PC", "SP", Endianness.LITTLE),
                  (Architecture.MIPS_BE, "MIPS - big endian", MIPS_REGS, "PC", "SP", Endianness.BIG),
                  (Architecture.MIPS64, "MIPS64 - little endian", MIPS_REGS, "PC", "SP", Endianness.LITTLE),
                  (Architecture.MIPS64_BE, "MIPS64 - big endian", MIPS_REGS, "PC", "SP", Endianness.BIG), ],

         # PPC is currently unsupported by unicorn: https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h#L94
         # "ppc": [ (Architecture.PPC, "PowerPC - big endian", PPC_REGS, "PC", "SP"),
         #          (Architecture.PPC64, "PowerPC64 - big endian", PPC_REGS, "PC", "SP"),],

         "sparc":[ (Architecture.SPARC, "SPARC - little endian", SPARC_REGS, "PC", "SP", Endianness.LITTLE),
                   (Architecture.SPARC_BE, "SPARC - big endian", SPARC_REGS, "PC", "SP", Endianness.BIG),
                   (Architecture.SPARC64, "SPARC64 - little endian", SPARC_REGS, "PC", "SP", Endianness.LITTLE),
                   (Architecture.SPARC64_BE, "SPARC64 - big endian", SPARC_REGS, "PC", "SP", Endianness.BIG),],
}


class Mode:
    DEFAULT_MODE = Architecture.X86_32_INTEL

    def __init__(self, *args, **kwargs):
        self.set_new_mode(Mode.DEFAULT_MODE)
        return

    def get_current_mode(self):
        return self.__selected

    def set_new_mode(self, i):
        for arch in modes.keys():
            for mode in modes[arch]:
                if mode[0]==i:
                    self.__selected = mode
                    self.__arch = arch
                    return

        raise Exception("Invalid arch/mode")

    def get_id(self):
        return self.__selected[0]

    def get_title(self):
        return self.__selected[1]

    def get_registers(self):
        return self.__selected[2]

    def get_pc(self):
        return self.__selected[3]

    def get_sp(self):
        return self.__selected[4]

    def get_endianness(self):
        return self.__selected[5]

    def is_big_endian(self):
        return self.get_endianness()==Endianness.BIG

    def __eq__(self, x):
        return x==self.get_id()

    def get_memory_alignment(self):
        if self.get_id() in (Architecture.X86_16_INTEL,
                               Architecture.ARM_THUMB_LE,
                               Architecture.ARM_THUMB_BE):
            return 16

        if self.get_id() in (Architecture.X86_64_INTEL,
                               Architecture.X86_64_ATT,
                               Architecture.ARM_AARCH64):
            return 64

        return 32

    def __str__(self):
        return self.get_title()

    @property
    def ptrsize(self):
        return self.get_memory_alignment()

    @property
    def endian_str(self):
        return "big" if self.is_big_endian() else "little"

    def get_syscalls(self):
        path = os.path.dirname(os.path.realpath(__file__)) + "/syscalls"

        if self.get_id() in (Architecture.X86_16_INTEL, Architecture.X86_32_INTEL, Architecture.X86_16_ATT, Architecture.X86_32_ATT):
            fname = "x86"
        elif self.get_id() in (Architecture.X86_64_INTEL, Architecture.X86_64_ATT,):
            fname = "x86-64"
        elif self.get_id() in (Architecture.ARM_AARCH64, ):
            fname = "aarch64"
        else:
            raise NotImplementedError("No syscalls for '{}'".format(str(self)))

        fpath = "{}/{}.csv".format(path, fname)
        syscalls = {}

        with open(fpath, 'r') as fd:
            reader = csv.reader(fd, delimiter=',')
            for row in reader:
                syscall_number, syscall_name = int(row[0]), row[1].lower().strip().encode()
                syscalls[syscall_name] = syscall_number

        return syscalls
