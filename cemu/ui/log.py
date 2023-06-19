from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QDockWidget, QFrame, QTextEdit

import cemu.log


class LogWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(LogWidget, self).__init__("Cemu Logs", parent)
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont("Courier", 11))
        self.__editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.__editor.setReadOnly(True)
        self.setWidget(self.__editor)
        cemu.log.register_sink(self.log)

    def log(self, msg: str) -> None:
        self.__editor.append(msg)

    def clear(self) -> None:
        self.__editor.clear()

    def __del__(self) -> None:
        cemu.log.unregister_sink(self.log)
