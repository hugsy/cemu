from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

# from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QDockWidget, QHBoxLayout, QPushButton, QWidget

import cemu.core
from cemu import utils
from cemu.emulator import Emulator, EmulatorState
from cemu.log import dbg, info
from cemu.ui.utils import PopupType, popup

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow


@dataclass
class CommandButton:
    label: str
    on_click: Callable
    shortcut: str


class CommandWidget(QDockWidget):
    # setCommandButtonsForRunningSignal = pyqtSignal()
    # setCommandButtonsForStepRunningSignal = pyqtSignal()
    # setCommandButtonsForStopSignal = pyqtSignal()

    def __init__(self, parent: CEmuWindow, *args, **kwargs):
        super().__init__("Control Panel", parent)
        self.root = parent
        sc = parent.shortcuts

        #
        # Layout setup
        #
        layout = QHBoxLayout()
        layout.addStretch(1)

        buttons = {
            "run": CommandButton(" ▶️▶️ ", self.onClickRunAll, "emulator_run_all"),
            "step": CommandButton(" ⏯️ ", self.onClickStepNext, "emulator_step"),
            "stop": CommandButton(" ⏹️ ", self.onClickStop, "emulator_stop"),
            "check": CommandButton(" ✅ ", self.onClickCheckCode, "emulator_check"),
        }

        self.buttons: dict[str, QPushButton] = {}
        for name in buttons:
            button = QPushButton(buttons[name].label)
            button.clicked.connect(buttons[name].on_click)
            button.setShortcut(sc.shortcut(buttons[name].shortcut))
            self.buttons[name] = button
            layout.addWidget(self.buttons[name])

        self.buttons["run"].setDisabled(False)
        self.buttons["step"].setDisabled(False)
        self.buttons["stop"].setDisabled(True)
        self.buttons["check"].setDisabled(False)

        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)

        # parent.signals[
        #     "setCommandButtonsRunState"
        # ] = self.setCommandButtonsForRunningSignal
        # self.setCommandButtonsForRunningSignal.connect(self.onSignalEmulationRun)

        # parent.signals[
        #     "setCommandButtonsStepRunState"
        # ] = self.setCommandButtonsForStepRunningSignal
        # self.setCommandButtonsForStepRunningSignal.connect(
        #     self.onSignalEmulationStepRun
        # )

        # parent.signals[
        #     "setCommandButtonStopState"
        # ] = self.setCommandButtonsForStopSignal
        # self.setCommandButtonsForStopSignal.connect(self.onEmulationStop)

        #
        # Emulator state callback
        #
        self.emulator: Emulator = cemu.core.context.emulator
        self.emulator.add_state_change_cb(EmulatorState.NOT_RUNNING, self.onResetState)
        self.emulator.add_state_change_cb(EmulatorState.RUNNING, self.onRunningState)
        self.emulator.add_state_change_cb(EmulatorState.IDLE, self.onIdleState)
        return

    def onClickStepNext(self) -> None:
        """
        Command to step into the next instruction. Enable the stepping mode in the emulator, then run.
        """
        self.emulator.use_step_mode = True
        self.emulator.stop_now = False
        self.emulator.set(EmulatorState.RUNNING)
        return

    def onClickStop(self):
        """
        Callback function for "Stop execution"
        """
        if not self.emulator.is_running:
            popup("Emulator is not running...")
            return

        dbg("Stopping emulation...")
        self.emulator.set(EmulatorState.FINISHED)
        info("Emulation context has stopped")
        return

    def onClickRunAll(self) -> None:
        """
        Command to run the emulation from $pc until the end of
        the code provided
        """
        self.emulator.use_step_mode = True
        self.emulator.stop_now = False
        self.emulator.set(EmulatorState.RUNNING)
        return

    def onClickCheckCode(self) -> None:
        """
        Callback function for performing a syntaxic check of the code in the code pane.
        """
        code = self.root.get_codeview_content()
        try:
            if not code:
                raise ValueError("Empty code")

            utils.assemble(code)
            title = "Success"
            msg = "Your code is syntaxically valid."
            popup_style = PopupType.Information
        except Exception as e:
            title = "Some errors were found in your code."
            msg = str(e)
            popup_style = PopupType.Error

        popup(msg, popup_style, title=title)
        return

    def onRunningState(self) -> None:
        """
        Signal callback called when notifying the start of emulation
        Enable the "Stop" button, disable the other ones
        """
        self.buttons["stop"].setDisabled(False)
        self.buttons["run"].setDisabled(True)
        self.buttons["step"].setDisabled(True)
        return

    def onResetState(self) -> None:
        """
        Signal callback called when notifying the step run of emulation
        Everything is enabled
        """
        self.buttons["stop"].setDisabled(False)
        self.buttons["run"].setDisabled(False)
        self.buttons["step"].setDisabled(False)
        return

    def onIdleState(self) -> None:
        """
        Signal callback called when notifying the end of emulation
        Enable the "Stop" button, disable the other ones
        """
        self.buttons["stop"].setDisabled(True)
        self.buttons["step"].setDisabled(False)
        self.buttons["run"].setDisabled(False)
        return
