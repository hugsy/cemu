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

class CommandWidget(QDockWidget):

    setCommandButtonsForRunningSignal = pyqtSignal()
    setCommandButtonsForStopSignal = pyqtSignal()

    def __init__(self, parent, *args, **kwargs):
        super(CommandWidget, self).__init__("Control Panel", parent)
        self.parent = self.parentWidget()
        self.root = self.parent
        self.log = self.root.log
        self.emulator = self.root.emulator
        sc = self.root.shortcuts
        layout = QHBoxLayout()
        layout.addStretch(1)

        self.__runButton = QPushButton("Run all code")
        self.__runButton.clicked.connect(self.run_until_end)
        self.__runButton.setShortcut(sc.shortcut("emulator_run_all"))

        self.__stepButton = QPushButton("Next instruction")
        self.__stepButton.clicked.connect(self.step_into)
        self.__stepButton.setShortcut(sc.shortcut("emulator_step"))

        self.__stopButton = QPushButton("Stop")
        self.__stopButton.setShortcut(sc.shortcut("emulator_stop"))
        self.__stopButton.clicked.connect( self.stop )
        self.__stopButton.setDisabled(True)

        self.__checkAsmButton = QPushButton("Check assembly code")
        self.__checkAsmButton.setShortcut(sc.shortcut("emulator_check"))
        self.__checkAsmButton.clicked.connect(self.check_assembly_code)

        layout.addWidget(self.__runButton)
        layout.addWidget(self.__stepButton)
        layout.addWidget(self.__stopButton)
        layout.addWidget(self.__checkAsmButton)

        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)

        self.root.signals["setCommandButtonsForRunning"] = self.setCommandButtonsForRunningSignal
        self.setCommandButtonsForRunningSignal.connect(self.onEmulationStart)

        self.root.signals["setCommandButtonsForStop"] = self.setCommandButtonsForStopSignal
        self.setCommandButtonsForStopSignal.connect(self.onEmulationStop)
        return


    def stop(self):
        if not self.emulator.is_running:
            self.log("No emulation context loaded.")
            return

        self.log("Stopping emulation...")
        self.emulator.stop()
        self.log("Emulation context has stopped")
        #self.registerWidget.updateGrid()

        # self.__stopButton.setDisabled(True)
        # self.__runButton.setDisabled(False)
        # self.__stepButton.setDisabled(False)
        return


    def step_into(self) -> None:
        """
        Command to step into the next instruction.
        """
        self.emulator.use_step_mode = True
        self.emulator.stop_now = False
        self.__run()
        return


    def run_until_end(self) -> None:
        """
        Command to run the emulation from $pc until the end of
        the code provided
        """
        self.emulator.use_step_mode = False
        self.emulator.stop_now = False
        self.__run()
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


    def check_assembly_code(self) -> bool:
        """
        Command to trigger a syntaxic check of the code in the code pane.
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


    def load_emulation_context(self) -> bool:
        """
        Prepare the emulation context based on the current context from the UI
        """
        self.emulator.reset()

        memory_layout = self.root.get_memory_layout()
        if not self.emulator.populate_memory(memory_layout):
            return False

        code = self.root.get_code(as_string=False)
        if not self.emulator.compile_code(code):
            return False

        regs = self.root.get_registers()
        if not self.emulator.populate_registers(regs):
            return False

        if not self.emulator.map_code():
            return False

        return True


    def onEmulationStart(self) -> None:
        self.__stopButton.setDisabled(False)
        return


    def onEmulationStop(self) -> None:
        self.__runButton.setDisabled(True)
        self.__stepButton.setDisabled(True)
        return