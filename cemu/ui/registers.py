from typing import Dict

from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QLabel,
    QTableWidgetItem,
    QWidget,
    QDockWidget,
)

from PyQt5.QtGui import(
    QFont,
    QColor
)

from PyQt5.QtCore import Qt

from ..utils import format_address


class RegistersWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(RegistersWidget, self).__init__("Registers", parent)
        self.parent = parent
        self.log = self.parent.log
        self.emulator = self.parent.emulator
        self.row_size = 15
        self.old_register_values = {}
        layout = QVBoxLayout()
        self.values = QTableWidget(10, 2)
        self.values.horizontalHeader().setStretchLastSection(True)
        self.values.setHorizontalHeaderLabels(["Register", "Value"])
        layout.addWidget(self.values)
        widget = QWidget()
        widget.setLayout(layout)
        self.setWidget(widget)
        self.updateGrid()
        return


    def updateGrid(self):
        emu = self.emulator
        current_mode = emu.arch
        registers = current_mode.registers
        self.values.setRowCount(len(registers))
        for i, reg in enumerate(registers):
            self.values.setRowHeight(i, self.row_size)
            name = QTableWidgetItem(reg)
            name.setFlags(Qt.NoItemFlags)
            val = emu.get_register_value(reg) if emu.vm else 0
            old_val = self.old_register_values.get(reg, 0)
            if type(val) in (int, int):
                value = format_address(val, current_mode)
            else:
                value = str(val)
            value = QTableWidgetItem( value )
            if old_val != val:
                self.old_register_values[reg] = val
                value.setForeground(QColor(Qt.red))
            value.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.values.setItem(i, 0, name)
            self.values.setItem(i, 1, value)
        return


    def getRegisters(self) -> Dict[str,int]:
        """
        Returns the register grid values as a dict.
        """
        regs = {}
        current_mode = self.parent.parent.arch
        registers = current_mode.registers
        for i, _ in enumerate(registers):
            name = self.values.item(i, 0).text()
            value = self.values.item(i, 1).text()
            regs[name] = int(value, 16)
        return regs