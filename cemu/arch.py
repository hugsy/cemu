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
                         "ARM_THUMB_BE")

X86_GPR = ["AX", "BX", "CX", "DX", "IP", "BP", "SP"]
X86_PGR = ["CS", "DS", "ES", "FS", "SS"]
X86_16_REGS = X86_GPR + X86_PGR
X86_32_REGS = ["E"+x for x in X86_GPR] + X86_PGR
X86_64_REGS = ["R"+x for x in X86_GPR] + X86_PGR

modes = {"x86" : [ (Architecture.X86_16_INTEL, "16bit, Intel syntax", X86_16_REGS),
                   (Architecture.X86_32_INTEL, "32bit, Intel syntax", X86_32_REGS),
                   (Architecture.X86_64_INTEL, "64bit, Intel syntax", X86_64_REGS),
                   (Architecture.X86_16_ATT, "16bit, AT&T syntax", X86_16_REGS),
                   (Architecture.X86_32_ATT, "32bit, AT&T syntax", X86_32_REGS),
                   (Architecture.X86_64_ATT, "64bit, AT&T syntax", X86_64_REGS), ],

         "arm": [ (Architecture.ARM_LE, "ARM - little endian", ["R0", "R1", "R2", "R3",]),
                  (Architecture.ARM_BE, "ARM - big endian", ["R0", "R1", "R2", "R3",]),
                  (Architecture.ARM_THUMB_LE, "ARM Thumb mode - little endian", ["R0", "R1", "R2", "R3",]),
                  (Architecture.ARM_THUMB_BE, "ARM Thumb mobe - big endian", ["R0", "R1", "R2", "R3",]),]
}

class Mode:

    def __init__(self, *args, **kwargs):
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

    def __eq__(self, x):
        return x==self.get_id()
