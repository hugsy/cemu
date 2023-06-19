from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

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
            "run": CommandButton(" ⏩ ", self.onClickRunAll, "emulator_run_all"),
            "step": CommandButton(" ⏯️ ", self.onClickStepNext, "emulator_step"),
            "stop": CommandButton(" ⏹️ ", self.onClickStop, "emulator_stop"),
            "reset": CommandButton(" 🔄️ ", self.onClickReset, "emulator_reset"),
            "check": CommandButton(" ✅ ", self.onClickCheckCode, "emulator_check"),
        }

        self.buttons: dict[str, QPushButton] = {}
        for name in buttons:
            button = QPushButton(buttons[name].label)
            button.clicked.connect(buttons[name].on_click)
            button.setShortcut(sc.shortcut(buttons[name].shortcut))
            self.buttons[name] = button
            layout.addWidget(self.buttons[name])

        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)

        #
        # Emulator state callback
        #
        self.emulator: Emulator = cemu.core.context.emulator

        self.emulator.add_state_change_cb(
            EmulatorState.NOT_RUNNING, self.onNotRunningUpdateCommandButtons
        )
        self.emulator.add_state_change_cb(
            EmulatorState.RUNNING, self.onRunningUpdateCommandButtons
        )
        self.emulator.add_state_change_cb(
            EmulatorState.IDLE, self.onIdleUpdateCommandButtons
        )
        self.emulator.add_state_change_cb(
            EmulatorState.FINISHED, self.onFinishedUpdateCommandButtons
        )
        return

    def onClickRunAll(self) -> None:
        """
        Command to run the emulation from $pc until the end of
        the code provided
        """
        self.emulator.use_step_mode = False
        # self.emulator.stop_now = False
        self.emulator.set(EmulatorState.RUNNING)
        return

    def onClickStepNext(self) -> None:
        """
        Command to step into the next instruction. Enable the stepping mode in the emulator, then run.
        """
        self.emulator.use_step_mode = True
        # self.emulator.stop_now = False
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

    def onClickReset(self):
        """
        Callback function for "Reset execution"
        """
        if self.emulator.state != EmulatorState.FINISHED:
            raise Exception("Should never be here")

        dbg("Tearing down VM on user demand...")
        self.emulator.set(EmulatorState.TEARDOWN)
        info("Emulation context reset")
        return

    def onClickCheckCode(self) -> None:
        """
        Callback function for performing a syntaxic check of the code in the code pane.
        """
        code = self.root.get_codeview_content()
        try:
            if not code:
                raise ValueError("Empty code")

            insns = utils.assemble(code)
            title = "Success"
            msg = f"Your code is syntaxically valid, {len(insns)} instructions compiled"
            popup_style = PopupType.Information
        except Exception as e:
            title = "Some errors were found in your code."
            msg = f"{e.__class__.__name__}: {str(e)}"
            popup_style = PopupType.Error

        popup(msg, popup_style, title=title)
        return

    def onRunningUpdateCommandButtons(self) -> None:
        """On `running` state, disable all buttons"""
        self.buttons["run"].setDisabled(True)
        self.buttons["step"].setDisabled(True)
        self.buttons["stop"].setDisabled(True)
        self.buttons["reset"].setDisabled(True)
        return

    def onNotRunningUpdateCommandButtons(self) -> None:
        """On `not running` state, we can do all but stop"""
        self.buttons["run"].setDisabled(False)
        self.buttons["step"].setDisabled(False)
        self.buttons["stop"].setDisabled(True)
        self.buttons["reset"].setDisabled(True)
        return

    def onIdleUpdateCommandButtons(self) -> None:
        """On `idle` state, we can either step more, run all or stop"""
        self.buttons["stop"].setDisabled(False)
        self.buttons["step"].setDisabled(False)
        self.buttons["run"].setDisabled(False)
        self.buttons["reset"].setDisabled(True)
        return

    def onFinishedUpdateCommandButtons(self):
        """In the finished state, we can only completely reset the emulation context"""
        self.buttons["run"].setDisabled(True)
        self.buttons["step"].setDisabled(True)
        self.buttons["stop"].setDisabled(True)
        self.buttons["reset"].setDisabled(False)
        return
