import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

import cemu.log
from cemu.const import DEFAULT_STYLE_PATH, ICON_PATH, DEBUG
from cemu.ui.main import CEmuWindow


def Cemu(args):
    app = QApplication(args)
    app.setStyleSheet(DEFAULT_STYLE_PATH.open().read())
    app.setWindowIcon(QIcon(str(ICON_PATH.absolute())))
    if DEBUG:
        cemu.log.register_sink(print)

    CEmuWindow(app)
    sys.exit(app.exec())
