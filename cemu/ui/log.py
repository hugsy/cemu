import time

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QDockWidget, QFrame, QTextEdit

from cemu.const import LOG_DEFAULT_TIMESTAMP_FORMAT, LOG_INSERT_TIMESTAMP


class LogWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(LogWidget, self).__init__("Cemu Logs", parent)
        self.parent = self.parentWidget()
        self.__editor = QTextEdit()
        self.__editor.setFont(QFont('Courier', 11))
        self.__editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.__editor.setReadOnly(True)
        self.setWidget(self.__editor)
        self.__use_timestamp = LOG_INSERT_TIMESTAMP
        self.__timestamp_format = LOG_DEFAULT_TIMESTAMP_FORMAT

    def log(self, msg: str) -> None:
        ts = ""
        if self.__use_timestamp:
            ts = time.strftime(self.__timestamp_format) + ": "
        self.__editor.append(f"{ts}{msg}")

    def error(self, msg: str) -> None:
        self.log(f"[ERROR] {msg}")

    def warn(self, msg: str) -> None:
        self.log(f"[WARNING] {msg}")

    def info(self, msg: str) -> None:
        self.log(f"[INFO] {msg}")

    def ok(self, msg: str) -> None:
        self.log(f"[SUCCESS] {msg}")

    def clear(self) -> None:
        self.__editor.clear()
