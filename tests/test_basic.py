import pathlib
import platform
import pytest
import subprocess
import tempfile
import time
import unittest

from cemu.core import GlobalContext
from cemu.emulator import Emulator, EmulatorState
from cemu.memory import MemorySection


MEMORY_MAP_DEFAULT_LAYOUT: list[MemorySection] = [
    MemorySection(".text", 0x00004000, 0x1000, "READ|EXEC"),
    MemorySection(".data", 0x00005000, 0x1000, "READ|WRITE"),
    MemorySection(".stack", 0x00006000, 0x4000, "READ|WRITE"),
    MemorySection(".misc", 0x0000A000, 0x1000, "READ|WRITE|EXEC"),
]


class EmulationTestRunner:
    """Runs an emulation test session"""

    def __init__(self, emu: Emulator):
        self.emu = emu
        return

    def run(self):
        assert self.emu.code
        assert self.emu.codelines
        assert self.emu.sections

        start_address = self.emu.pc() or self.emu.start_addr
        start_offset = start_address - self.emu.start_addr

        if self.emu.use_step_mode:
            insn = self.emu.next_instruction(
                self.emu.code[start_offset:], start_address
            )
            end_address = insn.end
        else:
            end_address = self.emu.start_addr + len(self.emu.code)

        self.emu.start(start_address, end_address)

        if self.emu.pc() == (self.emu.start_addr + len(self.emu.code)):
            self.emu.set(EmulatorState.FINISHED)
        else:
            self.emu.set(EmulatorState.IDLE)

        return


@pytest.mark.skipif(
    platform.system().lower() != "linux", reason="Tests only for Windows"
)
class TestEmulatorBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.context = GlobalContext()
        self.emu = self.context.emulator
        self.runner = EmulationTestRunner(self.emu)
        self.emu.reset()
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_basic(self):
        #
        # Create default memory layout
        #
        self.emu.sections = MEMORY_MAP_DEFAULT_LAYOUT

        #
        # Add some code
        #
        self.emu.codelines = """
xor rax, rax
inc rax
"""

        #
        # Run
        #
        self.emu.set(EmulatorState.RUNNING)

        #
        # Test
        #
        assert self.emu.registers["RAX"] == 1
