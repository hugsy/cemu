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
from cemu.const import (
    DEFAULT_REGISTER_VIEW_CHANGED_REGISTER_COLOR,
    DEFAULT_REGISTER_VIEW_REGISTER_FONT,
    DEFAULT_REGISTER_VIEW_REGISTER_FONT_SIZE,
)
from cemu.emulator import Emulator, EmulatorState
from cemu.arch import format_address
import cemu.emulator


class RegistersWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(RegistersWidget, self).__init__("Registers", parent)
        self.root = self.parentWidget()
        self.__row_size = 15
        self.__old_register_values = {}
        layout = QVBoxLayout()
        self.RegisterTableWidget = QTableWidget(10, 2)
        hHeader = self.RegisterTableWidget.horizontalHeader()
        if hHeader:
            hHeader.setStretchLastSection(True)
        self.RegisterTableWidget.setHorizontalHeaderLabels(["Register", "Value"])
        vHeader = self.RegisterTableWidget.verticalHeader()
        if vHeader:
            vHeader.setVisible(False)
        self.RegisterTableWidget.setColumnWidth(0, 80)
        layout.addWidget(self.RegisterTableWidget)

        #
        # Setup the widget layout
        #
        widget = QWidget()
        widget.setLayout(layout)
        self.setWidget(widget)
        # self.updateGrid()

        #
        # Emulator state callback
        #
        emu: Emulator = cemu.core.context.emulator
        emu.add_state_change_cb(EmulatorState.IDLE, self.onIdleRefreshRegisterGrid)
        emu.add_state_change_cb(EmulatorState.FINISHED, self.onFinishedRefreshRegisterGrid)
        emu.add_state_change_cb(EmulatorState.NOT_RUNNING, self.updateGrid)
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
            name.setFont(
                QFont(
                    DEFAULT_REGISTER_VIEW_REGISTER_FONT,
                    DEFAULT_REGISTER_VIEW_REGISTER_FONT_SIZE,
                )
            )
            val = emu.registers[reg]
            old_val = self.__old_register_values.get(reg, 0)
            if type(val) in (int, int):
                value = format_address(val, arch)
            else:
                value = str(val)
            value = QTableWidgetItem(value)
            value.setFont(
                QFont(
                    DEFAULT_REGISTER_VIEW_REGISTER_FONT,
                    DEFAULT_REGISTER_VIEW_REGISTER_FONT_SIZE,
                )
            )
            if old_val != val:
                self.__old_register_values[reg] = val
                value.setForeground(QColor(DEFAULT_REGISTER_VIEW_CHANGED_REGISTER_COLOR))
            value.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEditable)
            self.RegisterTableWidget.setItem(i, 0, name)
            self.RegisterTableWidget.setItem(i, 1, value)

        #
        # Propagate the change to the emulator
        #
        cemu.core.context.emulator.registers = cemu.emulator.EmulationRegisters(self.getRegisterValuesFromGrid())
        return

    def getRegisterValuesFromGrid(self) -> dict[str, int]:
        """Returns the current values of the registers, as shown by the widget grid"""
        regs = {}
        registers = cemu.core.context.emulator.registers.keys()
        for i in range(len(registers)):
            item1 = self.RegisterTableWidget.item(i, 0)
            name = item1.text() if item1 else ""

            item2 = self.RegisterTableWidget.item(i, 1)
            value = item2.text() if item2 else "0"
            regs[name] = int(value, 16)
        return regs

    def onIdleRefreshRegisterGrid(self) -> None:
        self.updateGrid()
        return

    onNotRunningRefreshRegisterGrid = onIdleRefreshRegisterGrid
    onFinishedRefreshRegisterGrid = onIdleRefreshRegisterGrid
