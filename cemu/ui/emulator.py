from PyQt5.QtWidgets import (
    QVBoxLayout,
    QTextEdit,
    QFrame,
    QDockWidget,
)

from PyQt5.QtGui import(
    QFont,
)

class EmulatorWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(EmulatorWidget, self).__init__("Emulator Logs", parent)
        self.parent = self.parentWidget()
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont('Courier', 11))
        self.__editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.__editor.setReadOnly(True)
        self.setWidget(self.__editor)
        return


    def log(self, msg: str) -> None:
        """
        Log a new event from the emulator
        """
        self.__editor.append(msg)
        return
