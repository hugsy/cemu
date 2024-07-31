from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QCheckBox,
    QDockWidget,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import cemu.core
from cemu.emulator import Emulator, EmulatorState
from cemu.log import error
from cemu.memory import MemorySection
from cemu.arch import format_address

from .utils import popup

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow


class MemoryMappingWidget(QDockWidget):
    def __init__(self, parent: "CEmuWindow"):
        super().__init__("Memory Map", parent)

        layout = QVBoxLayout()

        # the memory layout table
        self.MemoryMapTableWidget = QTableWidget(0, 4)
        self.MemoryMapTableWidget.setFixedWidth(350)
        self.MemoryMapTableWidget.setColumnWidth(0, 120)
        self.MemoryMapTableWidget.setColumnWidth(1, 120)
        self.MemoryMapTableWidget.setColumnWidth(2, 120)
        self.MemoryMapTableWidget.setColumnWidth(3, 120)
        self.MemoryMapTableWidget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.MemoryMapTableWidget.setHorizontalHeaderLabels(["Start", "End", "Name", "Permission"])
        vHeader = self.MemoryMapTableWidget.verticalHeader()
        if vHeader:
            vHeader.setVisible(False)
        layout.addWidget(self.MemoryMapTableWidget)

        # add/remove buttons
        buttons = QHBoxLayout()
        btn_add = QPushButton("Add Section")
        buttons.addWidget(btn_add)
        btn_add.clicked.connect(self.onAddSectionButtonClicked)
        buttons.addStretch(1)
        btn_del = QPushButton("Remove Section")
        btn_del.clicked.connect(self.onDeleteSectionButtonClicked)
        buttons.addWidget(btn_del)
        layout.addLayout(buttons)

        # assign the widget layout
        widget = QWidget()
        widget.setLayout(layout)
        self.setWidget(widget)

        #
        # Emulator state callback
        #
        self.emu: Emulator = cemu.core.context.emulator
        self.emu.add_state_change_cb(EmulatorState.NOT_RUNNING, self.onNotRunningUpdateMemoryMap)
        self.emu.add_state_change_cb(EmulatorState.RUNNING, self.onRunningDisableMemoryMapGrid)
        self.emu.add_state_change_cb(EmulatorState.IDLE, self.onIdleEnableMemoryMapGrid)
        self.emu.add_state_change_cb(EmulatorState.FINISHED, self.onFinishedEnableMemoryMapGrid)

    def onNotRunningUpdateMemoryMap(self) -> None:
        self.redraw_memory_map_table()

    def onRunningDisableMemoryMapGrid(self) -> None:
        self.MemoryMapTableWidget.setDisabled(True)

    def onIdleEnableMemoryMapGrid(self) -> None:
        self.MemoryMapTableWidget.setDisabled(False)

    onFinishedEnableMemoryMapGrid = onIdleEnableMemoryMapGrid

    def redraw_memory_map_table(self) -> None:
        """Re-draw the memory table widget from the emulator sections"""
        self.MemoryMapTableWidget.clearContents()

        for idx, section in enumerate(self.emu.sections):
            self.MemoryMapTableWidget.insertRow(idx)
            name = QTableWidgetItem(section.name)
            start_address = QTableWidgetItem(format_address(section.address))
            end_address = QTableWidgetItem(format_address(section.address + section.size))
            permission = QTableWidgetItem(str(section.permission))
            self.MemoryMapTableWidget.setItem(idx, 0, start_address)
            self.MemoryMapTableWidget.setItem(idx, 1, end_address)
            self.MemoryMapTableWidget.setItem(idx, 2, name)
            self.MemoryMapTableWidget.setItem(idx, 3, permission)

        self.MemoryMapTableWidget.setRowCount(len(self.emu.sections))
        return

    def onAddSectionButtonClicked(self) -> None:
        """
        Callback associated with the click of the "Add Section" button
        """
        self.add_or_edit_section_popup()
        return

    def onDeleteSectionButtonClicked(self) -> None:
        """
        Callback associated with the click of the "Remove Section" button
        """
        selection = self.MemoryMapTableWidget.selectionModel()
        if not selection or not selection.hasSelection():
            return

        indexes = [x.row() for x in selection.selectedRows()]

        for idx in range(len(self.emu.sections) - 1, 0, -1):
            if idx in indexes:
                del cemu.core.context.emulator.sections[idx]
        self.redraw_memory_map_table()
        return

    def add_or_edit_section_popup(self) -> None:
        """
        Popup that present a form with all info to submit to create a new section
        """
        msgbox = QMessageBox(self)
        wid = QWidget()

        name = QLabel("Name")
        nameEdit = QLineEdit()

        startAddress = QLabel("Start Address")
        startAddressEdit = QLineEdit()

        size = QLabel("Size")
        sizeEdit = QLineEdit()

        perm = QLabel("Permissions")
        permCheck = QWidget()
        permCheckLayout = QHBoxLayout()
        perm_read_btn = QCheckBox("Read")
        perm_write_btn = QCheckBox("Write")
        perm_exec_btn = QCheckBox("Execute")
        permCheckLayout.addWidget(perm_read_btn)
        permCheckLayout.addWidget(perm_write_btn)
        permCheckLayout.addWidget(perm_exec_btn)
        permCheck.setLayout(permCheckLayout)

        grid = QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(name, 1, 0)
        grid.addWidget(nameEdit, 1, 1)

        grid.addWidget(startAddress, 2, 0)
        grid.addWidget(startAddressEdit, 2, 1)

        grid.addWidget(size, 3, 0)
        grid.addWidget(sizeEdit, 3, 1)

        grid.addWidget(perm, 4, 0)
        grid.addWidget(permCheck, 4, 1)

        msgbox.setLayout(grid)
        msgbox.setGeometry(300, 300, 350, 300)

        msgbox.setWindowTitle("Add section")
        layout = msgbox.layout()
        assert layout
        wid.setLayout(grid)
        wid.setMinimumWidth(400)
        layout.addWidget(wid)

        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)

        ret = msgbox.exec()
        if ret == QMessageBox.StandardButton.Ok:
            name = nameEdit.text()
            address = int(startAddressEdit.text(), 0)
            size = int(sizeEdit.text(), 0)

            if name in (x.name for x in cemu.core.context.emulator.sections):
                error("section name already exists")
                return

            memory_set = (set(range(x.address, x.address + x.size)) for x in cemu.core.context.emulator.sections)
            current_set = set(range(address, address + size))
            for m in memory_set:
                if len(current_set & m) != 0:
                    error("memory intersection/overlapping not allowed")
                    return

            section_perm = []
            if perm_read_btn.isChecked():
                section_perm.append("READ")
            if perm_write_btn.isChecked():
                section_perm.append("WRITE")
            if perm_exec_btn.isChecked():
                section_perm.append("EXEC")
            try:
                section = MemorySection(name, address, size, "|".join(section_perm))
                cemu.core.context.emulator.sections.append(section)
                self.redraw_memory_map_table()
            except ValueError as ve:
                popup(f"MemorySection is invalid, reason: Invalid {str(ve)}")
                return

            if perm_exec_btn.isChecked():
                section_perm.append("EXEC")
            try:
                section = MemorySection(name, address, size, "|".join(section_perm))
                cemu.core.context.emulator.sections.append(section)
                self.redraw_memory_map_table()
            except ValueError as ve:
                popup(f"MemorySection is invalid, reason: Invalid {str(ve)}")

        return
