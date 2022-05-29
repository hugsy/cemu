from typing import Optional

from cemu.arch import Architecture

# PPC is currently unsupported by unicorn:
# see https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h#L94


class PowerPC(Architecture):
    name: str = "PowerPC 32bits"
    pc: str = "PC"
    sp: str = "SP"
    flag: Optional[str] = None
    registers: list[str] = [
        'R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7',
        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        'R16', 'R17', 'R18', 'R19', 'R20', 'R21', 'R22', 'R23',
        'R24', 'R25', 'R26', 'R27', 'R28', 'R29', 'R30', 'R31',
        pc,
    ]
    syscall_filename: str = "ppc"
    ptrsize: int = 4
