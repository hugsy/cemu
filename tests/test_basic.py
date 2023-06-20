import logging
import os
import platform
import unittest
from dataclasses import dataclass
from typing import Callable

import pytest

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
                self.emu.code[start_offset:], start_address
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


@pytest.mark.skipif(
    platform.system().lower() != "linux", reason="Tests only for Windows"
)
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

        @dataclass
        class GenericTestCase:
            arch: cemu.arch.Architecture
            codelines: str
            result: Callable

        matrix: list[GenericTestCase] = [
            GenericTestCase(
                cemu.arch.x86.X86(),
                os.linesep.join(["nop", "xor ax, ax", "inc ax", "nop"]),
                lambda: self.emu.registers["AX"] == 1,
            ),
            GenericTestCase(
                cemu.arch.x86.X86_32(),
                os.linesep.join(["nop", "xor eax, eax", "inc eax", "nop"]),
                lambda: self.emu.registers["EAX"] == 1,
            ),
            GenericTestCase(
                cemu.arch.x86.X86_64(),
                os.linesep.join(["nop", "xor rax, rax", "inc rax", "nop"]),
                lambda: self.emu.registers["RAX"] == 1,
            ),
        ]

        for tc in matrix:
            #
            # (Re-)Initialize the context
            #
            cemu.core.context.architecture = tc.arch
            self.emu.reset()
            self.emu.sections = MEMORY_MAP_DEFAULT_LAYOUT
            self.emu.codelines = tc.codelines
            self.emu.use_step_mode = False

            #
            # Run
            #
            self.emu.set(EmulatorState.RUNNING)

            #
            # Test
            #
            assert self.emu.state == EmulatorState.FINISHED
            assert tc.result()
