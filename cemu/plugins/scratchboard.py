from typing import Optional

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QDockWidget, QFrame, QTextEdit, QVBoxLayout

from cemu.log import error
from cemu.ui.highlighter import Highlighter
from cemu.ui.main import CEmuWindow


class ScratchboardWidget(QDockWidget):
    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super(ScratchboardWidget, self).__init__("Scratchboard", parent)
        self.parent = parent
        self.title = "Scratchboard"
        QVBoxLayout()
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont("Courier", 11))
        self.__editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.__highlighter = Highlighter(self.__editor, "rest")
        self.setWidget(self.__editor)
        return


def register(parent: CEmuWindow) -> Optional[QDockWidget]:
    try:
        return ScratchboardWidget(parent)
    except Exception as e:
        error(f"Failed to register 'ScratchboardWidget': {e}")
        return None
