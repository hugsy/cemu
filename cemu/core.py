# -*- coding: utf-8 -*-

import sys

from PyQt5.QtWidgets import(
    QApplication,
)

from PyQt5.QtGui import(
    QIcon
)

from .const import ICON_PATH
from .ui.main import CEmuWindow


def Cemu(args):
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
    CEmuWindow()
    sys.exit(app.exec_())
