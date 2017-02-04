# -*- coding: utf-8 -*-



class Shortcut:

    def __init__(self, *args, **kwargs):
        self._config = {
            # menubar
            "exit_application" :   ["Alt+F4", "Exit the application"],
            "generate_asm_file":   [None, "Save the content as a compilable Assembly file."],
            "generate_c_file":     [None, "Save the content as a compilable C file."],
            "save_as_binary":      ["Ctrl+N", "Save the content of the raw binary pane in a file."],
            "save_as_asm":         ["Ctrl+S", "Save the content of the assembly pane in a file."],
            "load_binary":         ["Ctrl+B", "Load a raw binary file."],
            "load_assembly":       ["Ctrl+O", "Load an assembly file."],
            "shortcut_popup":      ["Ctrl+P", "Show the Shortcut bindings"],
            "about_popup":         [None, "Generic information about CEMU"],

            # emulator
            "emulator_check":      ["Alt+C", "Check the assembly code from the assembly pane"],
            "emulator_run_all":    ["Alt+R", "Check and run the assembly code"],
            "emulator_step":       ["Alt+S", "Starts emulation by stepping into it"],
            "emulator_stop":       ["Alt+X", "Stop emulation"],
        }
        return

    def shortcut(self, attr):
        return self._config[attr][0]

    def description(self, attr):
        return self._config[attr][1]
