from __future__ import annotations

from typing import TYPE_CHECKING

import unicorn
from PyQt6.QtCore import QEvent, QFileInfo, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QDockWidget, QFrame, QHBoxLayout, QLabel,
                             QLineEdit, QTextEdit, QVBoxLayout, QWidget)

import cemu.core

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow
from cemu.utils import hexdump


class MemoryWidget(QDockWidget):

    refreshMemoryEditorSignal = pyqtSignal()

    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super(MemoryWidget, self).__init__("Memory Viewer", parent)
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Location"))
        self.address = QLineEdit()
        self.address.textChanged.connect(self.updateEditor)
        title_layout.addWidget(self.address)
        title_widget = QWidget()
        title_widget.setLayout(title_layout)
        title_widget.setMouseTracking(True)

        memview_layout = QVBoxLayout()
        self.__editor = QTextEdit()
        self.__editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.__editor.setFont(QFont('Courier', 10))
        self.__editor.setReadOnly(True)
        memview_layout.addWidget(title_widget)
        memview_layout.addWidget(self.__editor)

        widget = QWidget(self)
        widget.setLayout(memview_layout)
        self.setWidget(widget)

        # define signals
        self.refreshMemoryEditorSignal.connect(self.onRefreshMemoryEditor)
        parent.signals["refreshMemoryEditor"] = self.refreshMemoryEditorSignal
        return

    def updateEditor(self) -> None:
        arch = cemu.core.context.architecture
        emu = cemu.core.context.emulator
        if not emu.vm:
            self.__editor.setText("VM not initialized")
            return

        if not emu.is_running:
            self.__editor.setText("VM not running")
            return

        value = self.address.text()
        if value.lower().startswith("0x"):
            value = value[2:]

        if value.startswith("@"):
            # if the value of the "memory viewer" field starts with @.<section_name>
            try:
                addr = emu.lookup_map(value[1:])
            except KeyError:
                return

        elif value.startswith("$"):
            # if the value of the "memory viewer" field starts with $<register_name>
            reg_name = value[1:].upper()
            if reg_name not in arch.registers:
                return
            addr = emu.get_register_value(reg_name)
            if addr is None:
                return

        else:
            if not value.isdigit():
                return
            addr = int(value, 16)

        try:
            l = 256
            data = emu.vm.mem_read(addr, l)
            text = hexdump(data, base=addr)
            self.__editor.setText(text)
        except unicorn.unicorn.UcError:
            self.__editor.setText("Cannot read at address %x" % addr)

        return

    def onRefreshMemoryEditor(self) -> None:
        self.updateEditor()
        return
