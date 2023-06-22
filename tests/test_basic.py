import logging
import os
import unittest
from dataclasses import dataclass
from typing import Callable, ClassVar

import cemu.arch
import cemu.core
import cemu.log
from cemu.core import GlobalContext
from cemu.emulator import Emulator, EmulatorState
from cemu.memory import MemorySection

MEMORY_MAP_DEFAULT_LAYOUT: list[MemorySection] = [
    MemorySection(".text", 0x00004000, 0x1000, "READ|EXEC"),
    MemorySection(".data", 0x00005000, 0x1000, "READ|WRITE"),
    MemorySection(".stack", 0x00006000, 0x4000, "READ|WRITE"),
]

LOGGER = logging.getLogger(__name__)
cemu.log.register_sink(LOGGER.debug)


@dataclass
class GenericTestCase:
    arch: cemu.arch.Architecture
    codelines: str
    result: Callable


@dataclass
class X86_16TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.x86.X86()


@dataclass
class X86_32TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.x86.X86_32()


@dataclass
class X86_64TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.x86.X86_64()


@dataclass
class ArmTestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.arm.ARM()


@dataclass
class Arm64TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.arm.AARCH64()


@dataclass
class MipsTestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.mips.MIPS()


@dataclass
class Mips64TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.mips.MIPS64()


@dataclass
class SparcTestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.sparc.SPARC()


@dataclass
class Sparc64TestCase(GenericTestCase):
    arch: ClassVar[cemu.arch.Architecture] = cemu.arch.sparc.SPARC64()


class EmulationTestRunner:
    """Runs an emulation test session"""

    def __init__(self, emu: Emulator):
        self.emu = emu
        return

    def run(self):
        assert self.emu
        assert self.emu.code
        assert self.emu.codelines
        assert self.emu.sections

        start_address = self.emu.pc() or self.emu.start_addr
        start_offset = start_address - self.emu.start_addr
        last_insn_address = self.emu.start_addr + len(self.emu.code)

        if self.emu.use_step_mode:
            insn = self.emu.next_instruction(
                self.emu.code[start_offset:], start_address + start_offset
            )
            end_address = insn.end
        else:
            end_address = last_insn_address

        self.emu.start(start_address, end_address)

        if self.emu.pc() == last_insn_address:
            self.emu.set(EmulatorState.FINISHED)
        else:
            self.emu.set(EmulatorState.IDLE)

        return


class TestEmulatorBasic(unittest.TestCase):
    def __repr__(self) -> str:
        return "TestEmulatorBasic"

    def setUp(self) -> None:
        cemu.core.context = GlobalContext()
        assert cemu.core.context
        self.emu = cemu.core.context.emulator
        self.runner = EmulationTestRunner(self.emu)
        self.emu.set_threaded_runner(self.runner)
        self.emu.reset()
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_default_execute_assembly_regs(self):
        """The most basic test, using the default architecture (x64), execute until the end"""
        self.emu.sections = MEMORY_MAP_DEFAULT_LAYOUT
        self.emu.codelines = os.linesep.join(["xor rax, rax", "inc rax"])
        self.emu.set(EmulatorState.RUNNING)
        assert self.emu.pc() in self.emu.sections[0]
        assert self.emu.pc() == self.emu.sections[0].address + len(self.emu.code)
        assert self.emu.state == EmulatorState.FINISHED
        assert self.emu.registers["RAX"] == 1

    def test_matrix_execute_assembly_regs(self):
        """Test the emulation for all supported architectures, with very basic instructions"""

        matrix: list[GenericTestCase] = [
            X86_16TestCase(
                os.linesep.join(["nop", "xor ax, ax", "inc ax", "nop"]),
                lambda: self.emu.registers["AX"] == 1,
            ),
            X86_32TestCase(
                os.linesep.join(["nop", "xor eax, eax", "inc eax", "nop"]),
                lambda: self.emu.registers["EAX"] == 1,
            ),
            X86_64TestCase(
                os.linesep.join(["nop", "xor rax, rax", "inc rax", "nop"]),
                lambda: self.emu.registers["RAX"] == 1,
            ),
            ArmTestCase(
                os.linesep.join(["mov r0, 1", "add r0, r0, 1"]),
                lambda: self.emu.registers["R0"] == 2,
            ),
            Arm64TestCase(
                os.linesep.join(["mov x0, 1", "add x0, x0, 1"]),
                lambda: self.emu.registers["X0"] == 2,
            ),
            MipsTestCase(
                os.linesep.join(["addiu $v0, $zero, 1", "addi $v0, $v0, 1"]),
                lambda: self.emu.registers["V0"] == 2,
            ),
            SparcTestCase(
                os.linesep.join(["mov  1, %o0", "add %o0, 1, %o0"]),
                lambda: self.emu.registers["O0"] == 2,
            ),
            # Mips64TestCase(
            #     os.linesep.join(["addiu $v0, $zero, 1", "addi $v0, $v0, 1"]),
            #     lambda: self.emu.registers["V0"] == 2,
            # ),
            # Sparc64TestCase(
            #     os.linesep.join(["mov  1, %o0", "add %o0, 1, %o0"]),
            #     lambda: self.emu.registers["O0"] == 2,
            # ),
        ]

        for tc in matrix:
            #
            # (Re-)Initialize the context
            #
            cemu.core.context.architecture = tc.arch
            self.emu.reset()
            self.emu.sections = MEMORY_MAP_DEFAULT_LAYOUT[:]
            self.emu.codelines = tc.codelines[:]
            self.emu.use_step_mode = False

            #
            # Run
            #
            self.emu.set(EmulatorState.RUNNING)

            #
            # Test
            #
            # TODO Buggy - last PC value is not refreshed in unicorn for some archs
            if (
                isinstance(tc.arch, cemu.arch.x86.X86)
                or isinstance(tc.arch, cemu.arch.x86.X86_32)
                or isinstance(tc.arch, cemu.arch.x86.X86_64)
                or isinstance(tc.arch, cemu.arch.arm.ARM)
                or isinstance(tc.arch, cemu.arch.arm.AARCH64)
            ):
                assert self.emu.pc() == self.emu.sections[0].address + len(
                    self.emu.code
                )
                assert self.emu.state == EmulatorState.FINISHED

            assert tc.result()
