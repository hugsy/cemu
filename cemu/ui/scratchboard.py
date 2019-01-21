from PyQt5.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QTextEdit,
    QWidget
)

from PyQt5.QtGui import(
    QFont,
)

from .highlighter import Highlighter


class ScratchboardWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(ScratchboardWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        label = QLabel("Scratchboard")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.highlighter = Highlighter(self.editor, "rest")
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return