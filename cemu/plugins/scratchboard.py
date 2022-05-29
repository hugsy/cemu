from typing import Optional
from cemu.ui.main import CEmuWindow
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QTextEdit,
    QWidget,
    QDockWidget,
)

from PyQt6.QtGui import(
    QFont,
)

from cemu.ui.highlighter import Highlighter


class ScratchboardWidget(QDockWidget):
    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super(ScratchboardWidget, self).__init__("Scratchboard", parent)
        self.parent = parent
        self.title = "Scratchboard"
        layout = QVBoxLayout()
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont('Courier', 11))
        self.__editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.__highlighter = Highlighter(self.__editor, "rest")
        self.setWidget(self.__editor)
        return


def register(parent: CEmuWindow) -> Optional[QDockWidget]:
    try:
        return ScratchboardWidget(parent)
    except Exception as e:
        log(f"Failed to register 'ScratchboardWidget': {e}")
        return None
