import os
import sys
from typing import Optional

from cemu.log import error
from cemu.plugins import CemuPlugin
from cemu.ui.highlighter import Highlighter

from .console import PythonConsole

PLUGIN_NAME: str = "Python Console"


class PythonConsoleWidget(CemuPlugin):
    version = "{}.{}.{}-{}.{}".format(*sys.version_info)
    motd = [
        "",
        f"# Welcome to CEMU Python console (v{version})",
        "# You can interact with any emulator component (registers, memory, code, etc.).",
        "# The emulator is exposed via the `emu` object, and the VM via `vm`!",
        "",
    ]

    def __init__(self, parent):
        super().__init__(PLUGIN_NAME, parent)
        self.title = "Python"
        self.__console = PythonConsole(self, motd=os.linesep.join(self.motd))
        self.__highlighter = Highlighter(self.__console, "py")
        self.setWidget(self.__console)
        return


def register(parent) -> Optional[CemuPlugin]:
    try:
        return PythonConsoleWidget(parent)
    except Exception as e:
        error("Failed to register 'PythonConsoleWidget': {}".format(e))
        return None
