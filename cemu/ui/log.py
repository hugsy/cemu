from PyQt5.QtWidgets import (
    QVBoxLayout,
    QTextEdit,
    QFrame,
    QWidget
)

from PyQt5.QtGui import(
    QFont,
)

class LogWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(LogWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setReadOnly(True)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return