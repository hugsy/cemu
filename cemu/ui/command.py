from PyQt5.QtWidgets import (
    QPushButton,
    QHBoxLayout,
    QDockWidget,
    QWidget,
    QMessageBox,
)

class CommandWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CommandWidget, self).__init__("Control Panel", parent)
        self.parent = self.parentWidget()
        self.log = self.parent.log
        self.emulator = self.parent.emulator
        sc = self.parent.shortcuts
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
        return


    def stop(self):
        if not self.emulator.is_running:
            self.log("No emulation context loaded.")
            return

        self.emulator.stop()
        self.registerWidget.updateGrid()
        self.log("Emulation context reset")
        self.__stopButton.setDisabled(True)
        self.__runButton.setDisabled(False)
        self.__stepButton.setDisabled(False)
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
            self.emulator.is_running = True
            self.commandWidget.stopButton.setDisabled(False)

        self.emulator.run()
        self.registerWidget.updateGrid()
        self.memoryViewerWidget.updateEditor()
        return


    def check_assembly_code(self) -> bool:
        """
        Command to trigger a syntaxic check of the code in the code pane.
        """
        code = self.parent.get_code()
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

        memory_layout = self.parent.get_memory_layout()
        if not self.emulator.populate_memory(memory_layout):
            return False

        code = self.parent.get_code(as_string=False)
        if not self.emulator.compile_code(code):
            return False

        regs = self.parent.get_registers()
        if not self.emulator.populate_registers(regs):
            return False

        if not self.emulator.map_code():
            return False

        return True