from PyQt5.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QTextEdit,
    QWidget,
    QDockWidget,
)

from PyQt5.QtGui import(
    QFont,
)

from cemu.ui.highlighter import Highlighter


class ScratchboardWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(ScratchboardWidget, self).__init__("Scratchboard", parent)
        self.parent = parent
        self.title = "Scratchboard"
        layout = QVBoxLayout()
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont('Courier', 11))
        self.__editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.__highlighter = Highlighter(self.__editor, "rest")
        self.setWidget(self.__editor)
        return


def register(parent) -> object:
    log = parent.log
    try:
        return ScratchboardWidget(parent)
    except Exception as e:
        log("Failed to register 'ScratchboardWidget': {}".format(e))
        return None
