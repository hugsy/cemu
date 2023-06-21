import cemu.core

SHORTCUT_CONFIG_SECTION_NAME = "Shortcuts"


class ShortcutManager:
    def __init__(self, *args, **kwargs):
        self._defaults: dict[str, tuple[str, str]] = {
            # fmt: off
            # menubar
            "exit_application":    ("Alt+F4", "Exit the application"),
            "generate_asm_file":   ("", "Save the content as a compilable Assembly file."),
            "generate_c_file":     ("", "Save the content as a compilable C file."),
            "save_as_binary":      ("Ctrl+N", "Save the content of the raw binary pane in a file."),
            "save_as_asm":         ("Ctrl+S", "Save the content of the assembly pane in a file."),
            "load_binary":         ("Ctrl+B", "Load a raw binary file."),
            "load_assembly":       ("Ctrl+O", "Load an assembly file."),
            "shortcut_popup":      ("Ctrl+P", "Show the Shortcut bindings"),
            "about_popup":         ("", "Generic information about CEMU"),
            "generate_pe_exe":     ("", "Build a valid Windows PE executable"),
            "generate_elf_exe":    ("", "Build a valid Linux ELF executable"),
            "toggle_focus_mode":   ("Ctrl+F", "Toggle focus mode"),

            # emulator
            "emulator_check":      ("Alt+C", "Check the assembly code from the assembly pane"),
            "emulator_run_all":    ("Alt+R", "Check and run the assembly code"),
            "emulator_step":       ("Alt+S", "Starts emulation by stepping into it"),
            "emulator_stop":       ("Alt+X", "Stop emulation"),
            "emulator_reset":      ("", "Reset emulator"),
            # fmt: on
        }

        self._config: dict[str, tuple[str, str]] = {}
        self.load()
        return

    def shortcut(self, attr: str) -> str:
        return self._config[attr][0]

    def description(self, attr) -> str:
        return self._config[attr][1]

    def load(self) -> bool:
        """
        Load the shortcuts dict from either the config file if the value exists, or
        the defaults
        """
        settings = cemu.core.context.settings
        for key in self._defaults:
            default_shortcut, description = self._defaults[key]
            value = settings.get(SHORTCUT_CONFIG_SECTION_NAME, key, default_shortcut)
            settings.set(SHORTCUT_CONFIG_SECTION_NAME, key, value)
            self._config[key] = (value, description)

        return True
