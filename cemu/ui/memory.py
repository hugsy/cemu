from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QLineEdit,
    QTextEdit,
    QFrame,
    QLabel,
)

from PyQt5.QtGui import(
    QFont,
)

from PyQt5.QtCore import(
    QFileInfo
)

import unicorn

from cemu.utils import hexdump


class MemoryWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(MemoryWidget, self).__init__()
        self.parent = parent
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Memory viewer"))
        self.address = QLineEdit()
        self.address.textChanged.connect(self.updateEditor)
        title_layout.addWidget(self.address)
        title_widget = QWidget()
        title_widget.setLayout(title_layout)
        title_widget.setMouseTracking(True)

        memview_layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setFont(QFont('Courier', 10))
        self.editor.setReadOnly(True)
        memview_layout.addWidget(title_widget)
        memview_layout.addWidget(self.editor)
        self.setLayout(memview_layout)
        return

    def enterEvent(self, evt):
        return

    def leaveEvent(self, evt):
        return

    def mouseMoveEvent(self, evt):
        return

    def updateEditor(self):
        emu = self.parent.parent.emulator
        if emu.vm is None:
            self.editor.setText("VM not running")
            return

        value = self.address.text()
        if value.startswith("0x") or value.startswith("0X"):
            value = value[2:]

        if value.startswith("@"):
            # if the value of the "memory viewer" field starts with @.<section_name>
            addr = emu.lookup_map(value[1:])
            if addr is None:
                return

        elif value.startswith("$"):
            # if the value of the "memory viewer" field starts with $<register_name>
            reg_name = value[1:].upper()
            if reg_name not in emu.arch.registers:
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
            self.editor.setText(text)
        except unicorn.unicorn.UcError:
            self.editor.setText("Cannot read at address %x" % addr)

        return