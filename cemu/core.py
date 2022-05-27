import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from cemu.const import DEFAULT_STYLE_PATH, ICON_PATH
from cemu.ui.main import CEmuWindow


def Cemu(args):
    app = QApplication(args)
    app.setStyleSheet(DEFAULT_STYLE_PATH.open().read())
    app.setWindowIcon(QIcon(str(ICON_PATH.absolute())))
    CEmuWindow(app)
    sys.exit(app.exec())
