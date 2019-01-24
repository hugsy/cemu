import sys

from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel
)

from cemu.ui.highlighter import Highlighter
from cemu.console import PythonConsole


class PythonConsoleWidget(QWidget):

    version = "{}.{}.{}-{}.{}".format(*sys.version_info)
    motd = "[+] Welcome to CEMU Python console (v{})".format(version)

    def __init__(self, parent, *args, **kwargs):
        super(PythonConsoleWidget, self).__init__()
        self.parent = parent
        self.title = "Python"
        self.layout = QVBoxLayout()
        self.console = PythonConsole(startup_message=self.motd, parent=self)
        self.highlighter = Highlighter(self.console, "py")
        self.layout.addWidget(self.console)
        self.setLayout(self.layout)
        return


def register(parent):
    try:
        return PythonConsoleWidget(parent)
    except Exception as e:
        print("Failed to register 'PythonConsoleWidget': {}".format(e))
        return None
