# -*- coding: utf-8 -*-

#import binascii
#import functools
#import os

#import tempfile
#import time

#import unicorn
#from pygments import highlight
#from pygments.formatter import Formatter
#from pygments.lexers import *

#from cemu.arch import DEFAULT_ARCHITECTURE, Architectures, get_architecture_by_name
#from cemu.emulator import Emulator
#from cemu.parser import CodeParser
#from cemu.shortcuts import Shortcut
#from cemu.utils import *

import sys

from PyQt5.QtWidgets import(
    QApplication,
)

from PyQt5.QtGui import(
    QIcon
)

from cemu.const import ICON_PATH
from .ui.main import CEmuWindow


def Cemu():
    app = QApplication(sys.argv)
    style = """
    QMainWindow, QWidget{
    background-color: darkgray;
    }

    QTextEdit, QLineEdit, QTableWidget{
    background-color: white;
    }
    """
    app.setStyleSheet(style)
    app.setWindowIcon(QIcon(ICON_PATH))
    emu = CEmuWindow()
    sys.exit(app.exec_())
