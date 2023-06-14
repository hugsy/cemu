from PyQt6.QtCore import Qt

# from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDockWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import cemu.core
from cemu.emulator import Emulator, EmulatorState
from cemu.utils import format_address

UI_REGISTERS_CHANGED_VALUE_COLOR = "red"
UI_REGISTERS_REGISTER_NAME_FONT = ("Courier", 11)
UI_REGISTERS_REGISTER_VALUE_FONT = ("Courier", 11)


class RegistersWidget(QDockWidget):
    # refreshRegisterGridSignal = pyqtSignal()

    def __init__(self, parent, *args, **kwargs):
        super(RegistersWidget, self).__init__("Registers", parent)
        self.root = self.parentWidget()
        self.__row_size = 15
        self.__old_register_values = {}
        layout = QVBoxLayout()
        self.RegisterTableWidget = QTableWidget(10, 2)
        self.RegisterTableWidget.horizontalHeader().setStretchLastSection(True)
        self.RegisterTableWidget.setHorizontalHeaderLabels(["Register", "Value"])
        self.RegisterTableWidget.verticalHeader().setVisible(False)
        self.RegisterTableWidget.setColumnWidth(0, 60)
        layout.addWidget(self.RegisterTableWidget)

        #
        # Setup the widget layout
        #
        widget = QWidget()
        widget.setLayout(layout)
        self.setWidget(widget)
        self.updateGrid()

        #
        # Emulator state callback
        #
        emu: Emulator = cemu.core.context.emulator
        emu.add_state_change_cb(EmulatorState.IDLE, self.onIdleRefreshRegisterGrid)

        # # define signals
        # self.refreshRegisterGridSignal.connect(self.onRefreshRegisterGrid)
        # parent.signals["refreshRegisterGrid"] = self.refreshRegisterGridSignal
        return

    def updateGrid(self) -> None:
        """Refresh the grid values from the current values of the
        VM CPU registers

        """
        emu: Emulator = cemu.core.context.emulator
        arch = cemu.core.context.architecture
        registers = arch.registers
        self.RegisterTableWidget.setRowCount(len(registers))
        for i, reg in enumerate(registers):
            self.RegisterTableWidget.setRowHeight(i, self.__row_size)
            name = QTableWidgetItem(reg)
            name.setFlags(Qt.ItemFlag.NoItemFlags)
            name.setFont(QFont(*UI_REGISTERS_REGISTER_NAME_FONT))
            val = emu.get_register_value(reg) if emu.vm else 0
            old_val = self.__old_register_values.get(reg, 0)
            if type(val) in (int, int):
                value = format_address(val, arch)
            else:
                value = str(val)
            value = QTableWidgetItem(value)
            value.setFont(QFont(*UI_REGISTERS_REGISTER_VALUE_FONT))
            if old_val != val:
                self.__old_register_values[reg] = val
                value.setForeground(QColor(UI_REGISTERS_CHANGED_VALUE_COLOR))
            value.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEditable
            )
            self.RegisterTableWidget.setItem(i, 0, name)
            self.RegisterTableWidget.setItem(i, 1, value)

        #
        # Propagate the change to the emulator
        #
        cemu.core.context.emulator.registers = self.getRegisterValues()
        return

    def getRegisterValues(self) -> dict[str, int]:
        """Returns the current values of the registers, as shown by the widget grid"""
        regs = {}
        arch = cemu.core.context.architecture
        for i in range(len(arch.registers)):
            name = self.RegisterTableWidget.item(i, 0).text()
            value = self.RegisterTableWidget.item(i, 1).text()
            regs[name] = int(value, 16)
        return regs

    def onIdleRefreshRegisterGrid(self) -> None:
        self.updateGrid()
        return
