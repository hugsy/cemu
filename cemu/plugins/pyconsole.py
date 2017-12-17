# -*- coding: utf-8 -*-

import sys

from pygments import highlight
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from cemu.core import Highlighter
from cemu.console import PythonConsole


class PythonConsoleWidget(QWidget):

    version = "{}.{}.{}-{}.{}".format(*sys.version_info)
    motd = "[+] Welcome to CEMU Python console (v{})".format(version)

    def __init__(self, parent, *args, **kwargs):
        super(PythonConsoleWidget, self).__init__()
        self.parent = parent
        self.title = "Python Interpreter"
        self.layout = QVBoxLayout()
        self.layout.addWidget(QLabel(self.title))
        self.console = PythonConsole(startup_message=self.motd, parent=self)
        highlighter = Highlighter(self.console, "py")
        self.layout.addWidget(self.console)
        self.setLayout(self.layout)
        return


def register(parent):
    try:
        return PythonConsoleWidget(parent)
    except Exception as e:
        print("Failed to register 'PythonConsoleWidget': {}".format(e))
        return None
