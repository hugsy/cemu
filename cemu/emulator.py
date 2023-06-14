import os
from enum import IntEnum, unique
from multiprocessing import Lock
from typing import Any, Callable, Optional

import unicorn

import cemu.core
import cemu.utils
from cemu.log import dbg, error, info

from .arch import is_x86, is_x86_32, x86
from .memory import MemorySection


@unique
class EmulatorState(IntEnum):
    NOT_RUNNING = 0
    SETUP = 1
    IDLE = 2
    RUNNING = 3
    TEARDOWN = 5
    FINISHED = 6


class Emulator:
    EMU = 0
    LOG = 1

    def __init__(self):
        self.use_step_mode = False
        self.widget = None
        self.lock = Lock()
        self.__state_change_callbacks: dict[EmulatorState, list[Callable]] = {
            EmulatorState.NOT_RUNNING: [],
            EmulatorState.IDLE: [],
            EmulatorState.RUNNING: [],
            EmulatorState.FINISHED: [],
        }
        self.threaded_runner: Optional[object] = None
        self.reset()
        return

    def reset(self):
        self.vm: Optional[unicorn.Uc] = None
        self.ip: int = 0
        self.code: bytes = b""
        self.codelines: list[str] = []
        self.state = EmulatorState.NOT_RUNNING
        self.stop_now = False
        self.num_insns = -1
        self.sections: list[MemorySection] = []
        self.registers: dict[str, int] = {}

        #
        # Callback setup
        #
        [callbacks.clear() for _, callbacks in self.__state_change_callbacks.items()]
        self.add_state_change_cb(EmulatorState.RUNNING, self.setup)
        self.add_state_change_cb(EmulatorState.FINISHED, self.teardown)
        self.add_state_change_cb(EmulatorState.NOT_RUNNING, self.reset)
        return

    def __str__(self) -> str:
        return f"Emulator instance {'' if self.is_running else 'not '}running"

    def get_register_value(self, regname: str) -> int:
        """
        Returns an integer value of the register passed as a string.
        """

        if not self.vm:
            return -1

        arch = cemu.core.context.architecture

        # with self.lock:
        if True:
            ur = arch.uc_register(regname)
            val = self.vm.reg_read(ur)

        # TODO handle xmmreg later
        assert isinstance(val, int)
        return val

    regs = get_register_value

    def pc(self) -> int:
        """
        Returns the current value of $pc
        """
        return self.get_register_value(cemu.core.context.architecture.pc)

    def sp(self) -> int:
        """
        Returns the current value of $sp
        """
        return self.get_register_value(cemu.core.context.architecture.sp)

    def setup(self) -> None:
        """
        Create a new VM, and sets up the hooks
        """
        if self.vm:
            #
            # Environment already setup, just resume
            #
            return

        info("Setting up emulation environment...")

        arch = cemu.core.context.architecture
        self.vm = arch.uc
        self.vm.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
        self.vm.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)
        self.vm.hook_add(unicorn.UC_HOOK_INTR, self.hook_interrupt)  # type: ignore
        self.vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.vm.hook_add(unicorn.UC_HOOK_MEM_READ, self.hook_mem_access)
        if is_x86(cemu.core.context.architecture):
            self.vm.hook_add(
                unicorn.UC_HOOK_INSN,
                self.hook_syscall,
                None,
                1,
                0,
                unicorn.x86_const.UC_X86_INS_SYSCALL,
            )

        if not self.__populate_memory():
            raise Exception("populate_memory() failed")

        if not self.__populate_registers():
            raise Exception("populate_registers() failed")

        if not self.__populate_text_section():
            raise Exception("populate_text_section() failed")

        return

    def __populate_memory(self) -> bool:
        """
        Uses the information from `sections` to populate the unicorn VM memory layout
        """
        if not self.vm:
            error("VM is not initalized")
            return False

        for section in self.sections:
            self.vm.mem_map(section.address, section.size, int(section.permission))
            msg = f"Mapping {str(section)}"

            if section.content:
                self.vm.mem_write(section.address, section.content)
                msg += f", imported data '{len(section.content)}'"

            info(f"[vm::setup] {msg}")

        self.start_addr = self.sections[0].address
        self.end_addr = -1
        return True

    def __populate_registers(self) -> bool:
        """
        Populates the VM memory layout according to the values given as parameter.
        """
        if not self.vm:
            return False

        arch = cemu.core.context.architecture
        registers: dict[str, int] = self.registers

        #
        # Set the initial IP if unspecified
        #
        if registers[arch.pc] == 0:
            section_text = self.find_section(".text")
            registers[arch.pc] = section_text.address

        #
        # Set the initial SP if unspecified
        #
        if registers[arch.sp] == 0:
            section_stack = self.find_section(".stack")
            registers[arch.sp] = section_stack.address

        #
        # Populate all the registers for unicorn
        #
        if is_x86_32(arch):
            # create fake selectors
            ## required
            registers["CS"] = int(
                x86.X86_32.SegmentDescriptor(
                    0,
                    x86.X86_32.SegmentType.Code | x86.X86_32.SegmentType.Accessed,
                    False,
                    3,
                    True,
                )
            )
            registers["DS"] = int(
                x86.X86_32.SegmentDescriptor(
                    0,
                    x86.X86_32.SegmentType.Data | x86.X86_32.SegmentType.Accessed,
                    False,
                    3,
                    True,
                )
            )
            registers["SS"] = int(
                x86.X86_32.SegmentDescriptor(
                    0,
                    x86.X86_32.SegmentType.Data
                    | x86.X86_32.SegmentType.Accessed
                    | x86.X86_32.SegmentType.ExpandDown,
                    False,
                    3,
                    True,
                )
            )
            ## optional
            registers["GS"] = 0
            registers["FS"] = 0
            registers["ES"] = 0

        for r in registers.keys():
            ur = arch.uc_register(r)
            self.vm.reg_write(ur, registers[r])

        dbg(f"[vm::setup] Registers {registers}")
        return True

    def __generate_text_bytecode(self) -> bool:
        """
        Compile the assembly code using Keystone. Returns True if all went well,
        False otherwise.
        """
        nb_instructions = len(self.codelines)

        dbg(
            f"[vm::setup] Assembling {nb_instructions} instruction(s) for {cemu.core.context.architecture.name}"
        )

        try:
            insns = cemu.utils.assemble(
                os.linesep.join(self.codelines), base_address=self.start_addr
            )
            if len(insns) == 0:
                raise Exception("no instruction")
        except Exception as e:
            error(f"Failed to compile: error {str(e)}")
            return False

        self.code = b"".join([insn.bytes for insn in insns])
        dbg(f"[vm::setup] {len(insns)} instruction(s) compiled: {len(self.code)} bytes")

        self.end_addr = self.start_addr + len(self.code)
        return True

    def __populate_text_section(self) -> bool:
        if not self.vm:
            return False

        try:
            text_section = self.find_section(".text")
        except KeyError:
            #
            # Try to get the 1st executable section. Let the exception propagage if it fails
            #
            matches = [
                section for section in self.sections if section.permission.executable
            ]
            text_section = matches[0]

        info(f"Using text section {text_section}")

        if not self.__generate_text_bytecode():
            error("__generate_text_bytecode() failed")
            return False

        assert isinstance(self.code, bytes)

        dbg(
            f"Populated text section {text_section} with {len(self.code)} compiled bytes"
        )
        self.vm.mem_write(text_section.address, self.code)
        return True

    def next_instruction(self, code: bytes, addr: int) -> cemu.utils.Instruction:
        """
        Returns a string disassembly of the first instruction from `code`.
        """
        for insn in cemu.utils.disassemble(code, 1, addr):
            return insn

        raise Exception("should never be here")

    def hook_code(
        self, emu: unicorn.Uc, address: int, size: int, user_data: Any
    ) -> bool:
        """
        Unicorn instruction hook
        """
        if not self.vm:
            return False

        arch = cemu.core.context.architecture
        code = self.vm.mem_read(address, size)
        insn: cemu.utils.Instruction = self.next_instruction(code, address)
        if self.stop_now:
            self.start_addr = self.get_register_value(arch.pc)
            emu.emu_stop()
            return True

        dbg(f"[vm::runtime] Executing @ {insn}")

        if self.use_step_mode:
            self.stop_now = True
        return True

    def hook_block(self, emu: unicorn.Uc, addr: int, size: int, misc: Any) -> int:
        """
        Unicorn block change hook
        """
        dbg(f"[vm::runtime] Entering block at {addr:#x}")
        return 0

    def hook_interrupt(self, emu: unicorn.Uc, intno: int, data: Any) -> None:
        """
        Unicorn interrupt hook
        """
        dbg(f"[vm::runtime] Triggering interrupt #{intno:d}")
        return

    def hook_syscall(self, emu: unicorn.Uc, data: Any) -> int:
        """
        Unicorn syscall hook
        """
        dbg("[vm::runtime] Syscall")
        return 0

    def hook_mem_access(
        self,
        emu: unicorn.Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        extra: Any,
    ) -> None:
        if access == unicorn.UC_MEM_WRITE:
            info(f"Write: *{address:#x} = {value:#x} (size={size})")
        elif access == unicorn.UC_MEM_READ:
            info(f"Read: *{address:#x} (size={size})")
        return

    def run(self) -> None:
        """
        Runs the emulation
        """
        assert self.vm, "VM is not initialized"

        return

    def teardown(self) -> None:
        """
        Stops the unicorn environment
        """
        if not self.vm:
            return

        info("Ending emulation context")

        for section in self.sections:
            self.vm.mem_unmap(section.address, section.size)

        del self.vm
        self.vm = None
        return

    def find_section(self, section_name: str) -> MemorySection:
        """Lookup a particular section by its name

        Args:
            section_name (str): the name of the sections to search

        Raises:
            KeyError: if `section_name` not found

        Returns:
            MemorySection: _description_
        """
        matches = [section for section in self.sections if section.name == section_name]
        if not matches:
            raise KeyError(f"Section '{section_name}' not found")

        if len(matches) > 1:
            raise ValueError(f"Too many sections named {section_name}")

        return matches[0]

    def add_state_change_cb(self, new_state: EmulatorState, cb: Callable) -> None:
        """Register a callback triggered when the emulator switches to a new state

        Args:
            new_state (EmulatorState): the new state
            cb (Callable): the callback to execute when that happens
        """

        self.__state_change_callbacks[new_state].append(cb)
        return

    def set(self, new_state: EmulatorState):
        """Set the new state of the emulator, and invoke the associated callbacks

        Args:
            new_state (EmulatorState): the new state
        """
        if self.state == new_state:
            return

        dbg(f"Emulator is now in {new_state.name}")

        self.state = new_state
        assert int(self.state) == int(new_state), f"{self.state} != {new_state}"

        dbg(
            f"Executing {len(self.__state_change_callbacks)} callbacks for state {new_state.name}"
        )
        for new_state_cb in self.__state_change_callbacks[new_state]:
            dbg(f"Executing {new_state_cb.__name__}")
            res = new_state_cb()
            info(f"{new_state_cb.__name__}() return {res}")

        if new_state == EmulatorState.RUNNING:
            assert self.threaded_runner, "No threaded runner defined"
            assert callable(
                getattr(self.threaded_runner, "run")
            ), "Threaded runner is not runnable"
            self.threaded_runner.run()  # type: ignore
        return

    @property
    def is_running(self) -> bool:
        assert self.vm, "VM is not initialized"
        return self.state in (
            EmulatorState.RUNNING,
            EmulatorState.IDLE,
        )

    def set_threaded_runner(self, runnable_object: object):
        self.threaded_runner = runnable_object
