import sys

from PyQt5.QtWidgets import (
    QWidget,
    QDockWidget,
    QVBoxLayout,
    QLabel
)

from cemu.ui.highlighter import Highlighter
from cemu.console import PythonConsole


class PythonConsoleWidget(QDockWidget):

    version = "{}.{}.{}-{}.{}".format(*sys.version_info)
    motd = "[+] Welcome to CEMU Python console (v{})".format(version)
    motd+= "\nYou can interact with any emulator component (registers, memory, code, etc.)."
    motd+= "\nThe emulator is exposed via the `emu` object, and the VM via `vm`!"
    motd+= "\n"

    def __init__(self, parent, *args, **kwargs):
        super(PythonConsoleWidget, self).__init__("Python Console", parent)
        self.parent = self.parentWidget()
        self.title = "Python"
        self.__console = PythonConsole(self, motd=self.motd)
        self.__highlighter = Highlighter(self.__console, "py")
        self.setWidget(self.__console)
        return


def register(parent) -> object:
    log = parent.log
    try:
        return PythonConsoleWidget(parent)
    except Exception as e:
        log("Failed to register 'PythonConsoleWidget': {}".format(e))
        return None
