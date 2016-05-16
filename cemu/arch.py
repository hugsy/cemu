# -*- coding: utf-8 -*-

import enum

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
                         "SPARC " + \
                         "SPARC64 " + \
                         "SPARC64_BE" )

X86_GPR = ["AX", "BX", "CX", "DX", "SI", "DI", "IP", "BP", "SP"]
X86_PGR = ["CS", "DS", "ES", "FS", "GS", "SS"]
X86_16_REGS = X86_GPR
X86_32_REGS = ["E"+x for x in X86_GPR]
X86_64_REGS = ["R"+x for x in X86_GPR] + ["R%d"%i for i in range(8,16)]

ARM_GPR = ["R%d"%i for i in range(16)]
ARM_REGS = ARM_GPR + ["PC",]

AARCH64_GPR = ["X%d"%i for i in range(31)]
AARCH64_REGS = AARCH64_GPR + ["PC",]

MIPS_GPR = ["%d"%i for i in range(32)]
MIPS_REGS = AARCH64_GPR + ["PC",]

SPARC_GPR = ["G%d"%i for i in range(8)] + ["O%d"%i for i in range(8)] + ["L%d"%i for i in range(8)] + ["I%d"%i for i in range(8)]
SPARC_REGS = SPARC_GPR + ["PC",]

modes = {"x86":[ (Architecture.X86_16_INTEL, "16bit, Intel syntax", X86_16_REGS, "IP", "SP"),
                 (Architecture.X86_32_INTEL, "32bit, Intel syntax", X86_32_REGS, "EIP", "ESP"),
                 (Architecture.X86_64_INTEL, "64bit, Intel syntax", X86_64_REGS, "RIP", "RSP"),
                 (Architecture.X86_16_ATT, "16bit, AT&T syntax", X86_16_REGS, "IP", "SP"),
                 (Architecture.X86_32_ATT, "32bit, AT&T syntax", X86_32_REGS, "EIP", "ESP"),
                 (Architecture.X86_64_ATT, "64bit, AT&T syntax", X86_64_REGS, "RIP", "RSP"), ],

         "arm":[ (Architecture.ARM_LE, "ARM - little endian", ARM_REGS, "PC", "SP"),
                 (Architecture.ARM_BE, "ARM - big endian", ARM_REGS, "PC", "SP"),
                 (Architecture.ARM_THUMB_LE, "ARM Thumb mode - little endian", ARM_REGS, "PC", "SP"),
                 (Architecture.ARM_THUMB_BE, "ARM Thumb mobe - big endian", ARM_REGS, "PC", "SP"),
                 (Architecture.ARM_AARCH64, "ARMv8 AARCH64", AARCH64_REGS, "PC", "SP"), ],

         "mips":[ (Architecture.MIPS, "MIPS - little endian", MIPS_REGS, "PC", "SP"),
                  (Architecture.MIPS_BE, "MIPS - big endian", MIPS_REGS, "PC", "SP"),
                  (Architecture.MIPS64, "MIPS64 - little endian", MIPS_REGS, "PC", "SP"),
                  (Architecture.MIPS64_BE, "MIPS64 - big endian", MIPS_REGS, "PC", "SP"), ],

         "sparc":[ (Architecture.SPARC, "SPARC - little endian", SPARC_REGS, "PC", "SP"),
                   (Architecture.SPARC64, "SPARC64 - little endian", SPARC_REGS, "PC", "SP"),
                   (Architecture.SPARC64_BE, "SPARC64 - big endian", SPARC_REGS, "PC", "SP"),],
}


class Mode:

    def __init__(self, *args, **kwargs):
        # the default mode is x86 32b
        self.set_new_mode(Architecture.X86_32_INTEL)
        return

    def get_current_mode(self):
        return self.__selected

    def set_new_mode(self, i):
        for arch in modes.keys():
            for mode in modes[arch]:
                if mode[0]==i:
                    self.__selected = mode
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

    def __eq__(self, x):
        return x==self.get_id()
