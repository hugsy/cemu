import unicorn
from prompt_toolkit import prompt
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings

import cemu
import cemu.core
from cemu.emulator import EmulatorState
from cemu.log import dbg, error, info

bindings = KeyBindings()


@bindings.add("c-c")
def _(event):
    if cemu.core.context.emulator.is_running:
        cemu.core.context.emulator.set(EmulatorState.FINISHED)
    pass


class CEmuRepl:
    def __init__(self, args):
        super(CEmuRepl, self).__init__()
        assert cemu.core.context
        assert isinstance(cemu.core.context, cemu.core.GlobalContext)

        self.history = FileHistory(".cemu_history")

        self.keep_running = False
        self.prompt = "(cemu)> "
        self.__background_emulator_thread = EmulationRunner()
        cemu.core.context.emulator.set_threaded_runner(
            self.__background_emulator_thread
        )

        # register the callbacks for the emulator
        emu = cemu.core.context.emulator
        # emu.add_state_change_cb(
        #     EmulatorState.NOT_RUNNING, self.update_layout_not_running
        # )
        # emu.add_state_change_cb(EmulatorState.RUNNING, self.update_layout_running)
        # emu.add_state_change_cb(EmulatorState.IDLE, self.update_layout_step_running)
        # emu.add_state_change_cb(
        #     EmulatorState.FINISHED, self.update_layout_step_finished
        # )

        dbg("REPL initialized")

        #
        # set the emulator to a new context
        #
        emu.reset()
        return

    def run_forever(self):
        completer = NestedCompleter.from_nested_dict(
            {
                "regs": {
                    "set": None,
                    "get": None,
                },
                "memory": {
                    "add": None,
                    "del": None,
                    "view": None,
                },
                "arch": None,
                "code": None,
                "quit": None,
            }
        )

        self.keep_running = True
        while self.keep_running:
            #
            # Prompt
            #
            try:
                parts = (
                    prompt(
                        self.prompt,
                        history=self.history,
                        completer=completer,
                        auto_suggest=AutoSuggestFromHistory(),
                        bottom_toolbar=self.bottom_toolbar,
                    )
                    .strip()
                    .split()
                )

                command, args = (
                    parts[0].lower(),
                    parts[1:] if len(parts) else parts[0].lower(),
                    [],
                )

            except (KeyboardInterrupt, EOFError):
                self.keep_running = False
                continue

            #
            # Dispatch
            #
            match command:
                case "quit":
                    self.keep_running = False

                case "regs":
                    pass

                case _:
                    dbg(f"Executing {command=}")
        return

    def bottom_toolbar(self) -> str:
        return f"{str(cemu.core.context.emulator)}"


class EmulationRunner:
    """Runs an emulation session"""

    def run(self):
        """
        Runs the emulation
        """
        emu = cemu.core.context.emulator
        if not emu.vm:
            error("VM is not ready")
            return

        if not emu.is_running:
            error("Emulator is in invalid state")
            return

        try:
            start_address = emu.pc() or emu.start_addr
            start_offset = start_address - emu.start_addr

            #
            # Determine where to stop
            #
            if emu.use_step_mode:
                insn = emu.next_instruction(emu.code[start_offset:], start_address)
                end_address = insn.end
                info(f"Stepping from {start_address:#x} to {end_address:#x}")
            else:
                end_address = emu.start_addr + len(emu.code)
                info(f"Running all from {start_address:#x} to {end_address:#x}")

            with emu.lock:
                #
                # Run the emulator, let's go!
                #
                emu.vm.emu_start(start_address, end_address)

            #
            # If the execution is over, mark the state as finished
            #
            if emu.pc() == (emu.start_addr + len(emu.code)):
                emu.set(EmulatorState.FINISHED)
            else:
                emu.set(EmulatorState.IDLE)

        except unicorn.unicorn.UcError as e:
            error(f"An error occured: {str(e)} at pc={emu.pc():#x}, sp={emu.sp():#x}")
            emu.set(EmulatorState.FINISHED)

        return
