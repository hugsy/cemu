import os
import pathlib
import subprocess
import tempfile

import unicorn
from prompt_toolkit import prompt
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings

import cemu
import cemu.arch
import cemu.const
import cemu.core
import cemu.memory
from cemu.emulator import EmulatorState
from cemu.log import dbg, error, info, ok, warn
from cemu.utils import hexdump

bindings = KeyBindings()

TEXT_EDITOR = os.getenv("EDITOR") or "nano -c"

MEMORY_MAP_DEFAULT_LAYOUT: list[cemu.memory.MemorySection] = [
    cemu.memory.MemorySection(".text", 0x00004000, 0x1000, "READ|EXEC"),
    cemu.memory.MemorySection(".data", 0x00005000, 0x1000, "READ|WRITE"),
    cemu.memory.MemorySection(".stack", 0x00006000, 0x4000, "READ|WRITE"),
    cemu.memory.MemorySection(".misc", 0x0000A000, 0x1000, "READ|WRITE|EXEC"),
]


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

        self.history_filepath = pathlib.Path().home() / ".cemu_history"

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
        self.keep_running = True
        emu = cemu.core.context.emulator
        while self.keep_running:
            #
            # Refresh the completer values
            #
            menu_dict = {
                ".quit": None,
                ".version": None,
                ".debug": None,
                ".arch": {
                    "get": None,
                    "set": {x: None for x in cemu.arch.Architectures.keys()},
                },
                ".regs": {
                    "set": {x: None for x, _ in emu.registers.items()},
                    "get": {x: None for x, _ in emu.registers.items()},
                },
                ".mem": {
                    "default": None,
                    "list": None,
                    "add": None,
                    "del": None,
                    "view": None,
                    "edit": None,
                },
                ".reset": None,
                ".run": None,
                ".code": {
                    "show": None,
                    "check": None,
                    "edit": None,
                },
                ".step": {
                    "on": None,
                    "off": None,
                },
                # TODO everything below
                ".load": {
                    "asm": None,
                    "bin": None,
                    "minidump": None,
                    "coredump": None,
                },
                ".save": {
                    "asm": None,
                    "bin": None,
                    "pe": None,
                    "elf": None,
                },
            }
            completer = NestedCompleter.from_nested_dict(menu_dict)

            #
            # Prompt
            #
            try:
                line = prompt(
                    self.prompt,
                    history=FileHistory(str(self.history_filepath)),
                    completer=completer,
                    auto_suggest=AutoSuggestFromHistory(),
                    bottom_toolbar=self.bottom_toolbar,
                ).strip()

                if line.startswith("."):
                    #
                    # Entering a command ?
                    #
                    line = line[1:]
                    parts = line.split()
                    command, args = (
                        (parts[0].lower(), parts[1:])
                        if len(parts) >= 2
                        else (parts[0].lower(), [])
                    )
                else:
                    #
                    # It's assembly, happen and keep looping
                    #
                    emu.codelines += line + os.linesep
                    continue

            except (KeyboardInterrupt, EOFError):
                self.keep_running = False
                continue

            #
            # Dispatch
            #
            match command:
                case "help":
                    print(os.linesep.join([f" - {x}" for x in menu_dict.keys()]))

                case "version":
                    print(f"{cemu.const.PROGNAME} v{cemu.const.VERSION}")

                case "quit":
                    self.keep_running = False

                case "arch":
                    match args[0]:
                        case "get":
                            print(
                                f"Current architecture {cemu.core.context.architecture}"
                            )
                        case "set":
                            cemu.core.context.architecture = (
                                cemu.arch.Architectures.find(args[1])
                            )

                case "regs":
                    match args[0]:
                        case "get":
                            if len(args) == 1:
                                for regname, regvalue in emu.registers.items():
                                    print(f"{regname}={regvalue:#x}")
                            else:
                                print(f"{args[1]}={emu.registers[args[1]]:#x}")
                        case "set":
                            emu.registers[args[1]] = int(args[2])

                case "mem":
                    match args[0]:
                        case "default":
                            emu.sections = MEMORY_MAP_DEFAULT_LAYOUT[:]
                        case "list":
                            for idx, section in enumerate(emu.sections):
                                print(f"{idx:#04x}\t{section}")
                        case "add":
                            section = cemu.memory.MemorySection(
                                args[1], int(args[2], 0), int(args[3], 0), args[4]
                            )
                            emu.sections.append(section)
                            dbg(f"Section {section} added")
                        case "del":
                            section = emu.sections[int(args[1])]
                            emu.sections.remove(section)
                            dbg(f"Section {section} deleted")
                        case "view":
                            if emu.state not in (
                                EmulatorState.RUNNING,
                                EmulatorState.IDLE,
                                EmulatorState.FINISHED,
                            ):
                                warn("Emulator not running")
                            else:
                                assert emu.vm
                                address = int(args[1], 0)
                                size = int(args[2], 0)
                                data = emu.vm.mem_read(address, size)
                                print(hexdump(data, base=address))

                case "code":
                    match args[0]:
                        case "show":
                            info(f"{emu.codelines}")

                        case "check":
                            if emu.validate_assembly_code():
                                ok("Assembly code is valid")
                                print(hexdump(emu.code))
                            else:
                                error("Assembly code is invalid")

                        case "edit":
                            with tempfile.NamedTemporaryFile(
                                suffix=".asm", mode="w+"
                            ) as f:
                                filepath = pathlib.Path(f.name)
                                f.write(emu.codelines)
                                f.flush()
                                if subprocess.call([TEXT_EDITOR, filepath]) == 0:
                                    f.seek(0)
                                    emu.codelines = f.read()

                case "reset":
                    emu.reset()

                case "run":
                    emu.set(EmulatorState.RUNNING)

                case "step":
                    match args[0]:
                        case "on":
                            emu.use_step_mode = True
                        case "on":
                            emu.use_step_mode = False

                case "reset":
                    emu.set(EmulatorState.FINISHED)

                case "debug":
                    cemu.const.DEBUG = not cemu.const.DEBUG
                    ok(f"Debug is now {'on' if cemu.const.DEBUG else 'off'}")

                case _:
                    error(f"Executing {command=}")
        return

    def bottom_toolbar(self) -> str:
        return (
            f"{str(cemu.core.context.emulator)} [{str(cemu.core.context.architecture)}]"
        )


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
