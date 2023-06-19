from __future__ import annotations

from typing import TYPE_CHECKING

import unicorn
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import cemu.core
from cemu import const, utils
from cemu.emulator import Emulator, EmulatorState
from cemu.log import dbg

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow


class MemoryWidget(QDockWidget):
    # refreshMemoryEditorSignal = pyqtSignal()

    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super(MemoryWidget, self).__init__("Memory Viewer", parent)
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Location"))
        self.address = QLineEdit()
        self.address.textChanged.connect(self.updateEditor)
        self.alignement = QComboBox()
        self.alignement.addItems(["4", "8", "16"])
        self.alignement.setCurrentIndex(2)
        self.alignement.currentIndexChanged.connect(self.updateEditor)
        title_layout.addWidget(self.address)
        title_layout.addWidget(self.alignement)
        title_widget = QWidget()
        title_widget.setLayout(title_layout)
        title_widget.setMouseTracking(True)

        memview_layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.editor.setFont(
            QFont(const.DEFAULT_MEMORY_VIEW_FONT, const.DEFAULT_MEMORY_VIEW_FONT_SIZE)
        )
        self.editor.setReadOnly(True)
        memview_layout.addWidget(title_widget)
        memview_layout.addWidget(self.editor)

        widget = QWidget(self)
        widget.setLayout(memview_layout)
        self.setWidget(widget)

        #
        # Emulator state callback
        #
        emu: Emulator = cemu.core.context.emulator
        emu.add_state_change_cb(EmulatorState.IDLE, self.onIdleRefreshMemoryEditor)
        emu.add_state_change_cb(
            EmulatorState.FINISHED, self.onFinishedClearMemoryEditor
        )

        return

    def updateEditor(self) -> None:
        arch = cemu.core.context.architecture
        emu = cemu.core.context.emulator
        if not emu.vm:
            self.editor.setText("VM not initialized")
            return

        if not emu.is_running:
            self.editor.setText("VM not running")
            return

        addr: int
        msg = "Displaying "

        value = self.address.text()
        if value.lower().startswith("0x"):
            value = value[2:]

        if value.startswith("@"):
            # if the value of the "memory viewer" field starts with @.<section_name>
            section_name = value[1:]
            try:
                section = emu.find_section(section_name)
                addr = section.address
                msg += f"from section name {section_name}"
            except KeyError:
                self.editor.setText(f"No section named '{section_name}'")
                return

        elif value.startswith("$"):
            # if the value of the "memory viewer" field starts with $<register_name>
            reg_name = value[1:].upper()
            if reg_name not in arch.registers:
                return
            addr = emu.get_register_value(reg_name)
            if not addr:
                return
            msg += f" from register {reg_name}"

        else:
            if not value.isdigit():
                return
            addr = int(value, 16)
            msg += f" from value {value}"

        dbg(msg + f": {addr:#x}")

        assert isinstance(addr, int)

        try:
            alignment = int(self.alignement.currentText())
            data = emu.vm.mem_read(addr, const.DEFAULT_MEMORY_VIEW_CHUNK_SIZE)
            self.editor.setText(utils.hexdump(data, alignment, base=addr))
        except unicorn.unicorn.UcError:
            self.editor.setText("Cannot read at address %x" % addr)

        return

    def onIdleRefreshMemoryEditor(self) -> None:
        self.updateEditor()
        return

    def onFinishedClearMemoryEditor(self) -> None:
        self.editor.setText("")
        return
