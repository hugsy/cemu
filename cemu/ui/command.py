from PyQt5.QtCore import (
    QEvent,
    pyqtSignal,
)


from PyQt5.QtWidgets import (
    QPushButton,
    QHBoxLayout,
    QDockWidget,
    QWidget,
    QMessageBox,
)


from ..emulator import (
    EmulatorState
)


class CommandWidget(QDockWidget):

    setCommandButtonsForRunningSignal = pyqtSignal()
    setCommandButtonsForStepRunningSignal = pyqtSignal()
    setCommandButtonsForStopSignal = pyqtSignal()

    def __init__(self, parent: QWidget, *args, **kwargs):
        super(CommandWidget, self).__init__("Control Panel", parent)
        self.parent = self.parentWidget()
        self.root = self.parent
        self.log = self.root.log
        self.emulator = self.root.emulator
        sc = self.root.shortcuts
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
        self.__stopButton.clicked.connect( self.onClickStop )
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

        self.root.signals["setCommandButtonsRunState"] = self.setCommandButtonsForRunningSignal
        self.setCommandButtonsForRunningSignal.connect(self.onSignalEmulationRun)

        self.root.signals["setCommandButtonsStepRunState"] = self.setCommandButtonsForStepRunningSignal
        self.setCommandButtonsForStepRunningSignal.connect(self.onSignalEmulationStepRun)

        self.root.signals["setCommandButtonStopState"] = self.setCommandButtonsForStopSignal
        self.setCommandButtonsForStopSignal.connect(self.onEmulationStop)
        return


    def __run(self) -> None:
        """
        Internal method that starts the emulation
        """

        if not self.emulator.is_running:
            if not self.load_emulation_context():
                self.log("An error occured when loading context")
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
            self.log("Emulator is not running...")
            return

        self.log("Stopping emulation...")
        self.emulator.set_vm_state(EmulatorState.FINISHED)
        self.log("Emulation context has stopped")
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
        code = self.root.get_code()
        if self.emulator.compile_code(code, False):
            msg = "Your code is syntaxically valid."
            popup = QMessageBox.information
            is_valid = True
        else:
            msg = "Some errors were found in your code, check the logs..."
            popup = QMessageBox.warning
            is_valid = False

        popup(self,"Checking assembly code syntax...", msg)
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
        code = self.root.get_code(as_string=False)
        memory_layout = self.root.get_memory_layout()
        regs = self.root.get_registers()

        return  self.emulator.populate_memory(memory_layout) and \
                self.emulator.compile_code(code) and \
                self.emulator.populate_registers(regs) and \
                self.emulator.map_code()


