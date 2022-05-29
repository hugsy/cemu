from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (QDockWidget, QHBoxLayout, QMessageBox,
                             QPushButton, QWidget)

from cemu.log import dbg, error, info

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow

import cemu.core

from ..emulator import Emulator, EmulatorState


class CommandWidget(QDockWidget):

    setCommandButtonsForRunningSignal = pyqtSignal()
    setCommandButtonsForStepRunningSignal = pyqtSignal()
    setCommandButtonsForStopSignal = pyqtSignal()

    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super().__init__("Control Panel", parent)
        self.emulator: Emulator = cemu.core.context.emulator
        sc = parent.shortcuts
        layout = QHBoxLayout()
        layout.addStretch(1)

        self.__runButton = QPushButton("Run all code")
        self.__runButton.clicked.connect(self.onClickRunAll)
        self.__runButton.setShortcut(sc.shortcut("emulator_run_all"))

        self.__stepButton = QPushButton("Step to Next")
        self.__stepButton.clicked.connect(self.onClickStepNext)
        self.__stepButton.setShortcut(sc.shortcut("emulator_step"))

        self.__stopButton = QPushButton("Stop")
        self.__stopButton.setShortcut(sc.shortcut("emulator_stop"))
        self.__stopButton.clicked.connect(self.onClickStop)
        self.__stopButton.setDisabled(True)

        self.__checkAsmButton = QPushButton("Check assembly")
        self.__checkAsmButton.setShortcut(sc.shortcut("emulator_check"))
        self.__checkAsmButton.clicked.connect(self.onClickCheckCode)

        layout.addWidget(self.__runButton)
        layout.addWidget(self.__stepButton)
        layout.addWidget(self.__stopButton)
        layout.addWidget(self.__checkAsmButton)

        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)

        parent.signals["setCommandButtonsRunState"] = self.setCommandButtonsForRunningSignal
        self.setCommandButtonsForRunningSignal.connect(
            self.onSignalEmulationRun)

        parent.signals["setCommandButtonsStepRunState"] = self.setCommandButtonsForStepRunningSignal
        self.setCommandButtonsForStepRunningSignal.connect(
            self.onSignalEmulationStepRun)

        parent.signals["setCommandButtonStopState"] = self.setCommandButtonsForStopSignal
        self.setCommandButtonsForStopSignal.connect(self.onEmulationStop)
        return

    def __run(self) -> None:
        """
        Internal method that starts the emulation
        """

        if not self.emulator.is_running:
            if not self.load_emulation_context():
                error("An error occured when loading context")
                return

        self.emulator.run()
        return

    def onClickStepNext(self) -> None:
        """
        Command to step into the next instruction.
        """
        self.emulator.use_step_mode = True
        self.emulator.stop_now = False
        self.__run()
        return

    def onClickStop(self):
        """
        Callback function for "Stop execution"
        """
        if not self.emulator.is_running:
            error("Emulator is not running...")
            return

        info("Stopping emulation...")
        self.emulator.set_vm_state(EmulatorState.FINISHED)
        ("Emulation context has stopped")
        return

    def onClickRunAll(self) -> None:
        """
        Command to run the emulation from $pc until the end of
        the code provided
        """
        self.emulator.use_step_mode = False
        self.emulator.stop_now = False
        self.__run()
        return

    def onClickCheckCode(self) -> bool:
        """
        Callback function for performing a syntaxic check of the code in the code pane.
        """
        code = cemu.core.context.root.get_codeview_content()
        if self.emulator.assemble_code(code, False):
            msg = "Your code is syntaxically valid."
            popup = QMessageBox.information
            is_valid = True
        else:
            msg = "Some errors were found in your code, check the logs..."
            popup = QMessageBox.warning
            is_valid = False

        popup(self, "Checking assembly code syntax...", msg)
        return is_valid

    def onSignalEmulationRun(self) -> None:
        """
        Signal callback called when notifying the start of emulation
        """
        # enable the "Stop" button, disable the other ones
        self.__stopButton.setDisabled(False)
        self.__runButton.setDisabled(True)
        self.__stepButton.setDisabled(True)
        return

    def onSignalEmulationStepRun(self) -> None:
        """
        Signal callback called when notifying the step run of emulation
        """
        # everything is enabled
        self.__stopButton.setDisabled(False)
        self.__runButton.setDisabled(False)
        self.__stepButton.setDisabled(False)
        return

    def onEmulationStop(self) -> None:
        """
        Signal callback called when notifying the end of emulation
        """
        # enable the "Stop" button, disable the other ones
        self.__stopButton.setDisabled(True)
        self.__stepButton.setDisabled(False)
        self.__runButton.setDisabled(False)
        return

    def load_emulation_context(self) -> bool:
        """
        Prepare the emulation context based on the current context from the UI
        """
        self.emulator.reset()
        self.emulator.create_new_vm()
        code = cemu.core.context.root.get_codeview_content()
        memory_layout = cemu.core.context.root.get_memory_layout()
        regs = cemu.core.context.root.get_registers()

        return self.emulator.populate_memory(memory_layout) and \
            self.emulator.assemble_code(code) and \
            self.emulator.populate_registers(regs) and \
            self.emulator.map_code()
