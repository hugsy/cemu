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
    # fmt: off
    NOT_RUNNING = 0              # Nothing is initialized
    # SETUP = 1
    IDLE = 2                     # The VM is running but stopped: used for stepping mode
    RUNNING = 3                  # The VM is running
    TEARDOWN = 5
    FINISHED = 6                 # The VM has reached the end of the execution
    # fmt: on


class Emulator:
    def __init__(self):
        self.use_step_mode = False
        self.widget = None
        self.lock = Lock()
        self.state: EmulatorState = EmulatorState.NOT_RUNNING
        self.__state_change_callbacks: dict[EmulatorState, list[Callable]] = {
            EmulatorState.NOT_RUNNING: [],
            EmulatorState.IDLE: [],
            EmulatorState.RUNNING: [],
            EmulatorState.TEARDOWN: [],
            EmulatorState.FINISHED: [],
        }
        self.threaded_runner: Optional[object] = None
        self.vm: Optional[unicorn.Uc] = None
        self.code: bytes = b""
        self.codelines: str = ""
        self.sections: list[MemorySection] = []
        self.registers: dict[str, int] = {}
        self.start_addr: int = 0

        #
        # A call to `reset` **MUST** be done once the program is fully loaded
        #
        return

    def reset(self):
        self.vm = None
        self.code = b""
        self.codelines = ""
        self.sections = []
        self.registers = {name: 0 for name in cemu.core.context.architecture.registers}
        self.start_addr = 0
        self.set(EmulatorState.NOT_RUNNING)
        return

    def __str__(self) -> str:
        if self.is_running:
            return f"Emulator is running, IP={self.pc()}, SP={self.sp()}"
        return "Emulator instance is not running"

    def get_register_value(self, regname: str) -> int:
        """
        Returns an integer value of the register passed as a string.
        """

        if not self.vm:
            error("get_register_value() failed: VM not initialized")
            return -1

        arch = cemu.core.context.architecture
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
        dbg(
            f"[vm::setup] Generating assembly code for {cemu.core.context.architecture.name}"
        )

        try:
            insns = cemu.utils.assemble(self.codelines, base_address=self.start_addr)
            if len(insns) == 0:
                raise Exception("no instruction")
        except Exception as e:
            error(f"Failed to compile: exception {e.__class__.__name__}: {str(e)}")
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

        # arch = cemu.core.context.architecture
        code = self.vm.mem_read(address, size)
        insn: cemu.utils.Instruction = self.next_instruction(code, address)
        # if self.stop_now:
        #     self.start_addr = self.get_register_value(arch.pc)
        #     emu.emu_stop()
        #     return True

        if self.use_step_mode:
            dbg(f"[vm::runtime] Stepping @ {insn}")
        else:
            dbg(f"[vm::runtime] Executing @ {insn}")

        # if self.use_step_mode:
        #     self.stop_now = True
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

    def teardown(self) -> None:
        """
        Stops the unicorn environment
        """
        if not self.vm:
            return

        info(f"Ending emulation context at {self.pc():#x}")

        for section in self.sections:
            dbg(f"[vm::teardown] Unmapping {section}")
            self.vm.mem_unmap(section.address, section.size)

        dbg(f"[vm::teardown] Deleting {self.vm}")
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

        def assign_state(__new_state: EmulatorState):
            if self.state == __new_state:
                return

            info(f"Emulator is now {__new_state.name}")

            self.state = __new_state
            assert int(self.state) == int(__new_state), f"{self.state} != {__new_state}"

        assign_state(new_state)

        match new_state:
            case EmulatorState.RUNNING | EmulatorState.IDLE:
                #
                # Make sure there's always an emulation environment ready
                #
                self.setup()

            case _:
                pass

        dbg(
            f"Executing {len(self.__state_change_callbacks[new_state])} callbacks for state {new_state.name}"
        )

        for new_state_cb in self.__state_change_callbacks[new_state]:
            function_name = f"{new_state_cb.__module__}.{new_state_cb.__class__.__qualname__}.{new_state_cb.__name__}"
            res = new_state_cb()
            dbg(f"{function_name}() return {res}")

        match new_state:
            case EmulatorState.RUNNING:
                #
                # This will effectively trigger the execution in unicorn
                #
                assert self.threaded_runner, "No threaded runner defined"
                assert callable(
                    getattr(self.threaded_runner, "run")
                ), "Threaded runner is not runnable"
                self.threaded_runner.run()  # type: ignore

            case EmulatorState.TEARDOWN:
                #
                # When the execution is finished, cleanup and switch back to a "NotRunning" state
                # This is done to make sure all the callback can still access the VM
                #
                self.teardown()

                #
                # Completely reset the emulation envionment, and set the status to NOT_RUNNING
                #
                self.reset()

            case _:
                pass

        return

    @property
    def is_running(self) -> bool:
        return self.state in (
            EmulatorState.RUNNING,
            EmulatorState.IDLE,
        )

    def set_threaded_runner(self, runnable_object: object):
        self.threaded_runner = runnable_object

    def context(self) -> dict[str, int]:
        """Get the current context for the registers as a hash table

        Returns:
            dict[str, Union[int, str]]: _description_
        """
        if not self.vm:
            return {}
        regs = {name: self.get_register_value(name) for name in self.registers}
        return regs
