from PyQt5.QtWidgets import (
    QPushButton,
    QHBoxLayout,
    QWidget
)

class CommandWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CommandWidget, self).__init__()
        self.parent = parent
        sc = self.parent.parent.shortcuts
        layout = QHBoxLayout()
        layout.addStretch(1)

        self.runButton = QPushButton("Run all code")
        self.runButton.clicked.connect(self.parent.runCode)
        self.runButton.setShortcut(sc.shortcut("emulator_run_all"))

        self.stepButton = QPushButton("Next instruction")
        self.stepButton.clicked.connect(self.parent.stepCode)
        self.stepButton.setShortcut(sc.shortcut("emulator_step"))

        self.stopButton = QPushButton("Stop")
        self.stopButton.setShortcut(sc.shortcut("emulator_stop"))
        self.stopButton.clicked.connect( self.parent.stopCode )

        self.checkAsmButton = QPushButton("Check assembly code")
        self.checkAsmButton.setShortcut(sc.shortcut("emulator_check"))
        self.checkAsmButton.clicked.connect(self.parent.checkAsmCode)

        layout.addWidget(self.runButton)
        layout.addWidget(self.stepButton)
        layout.addWidget(self.stopButton)
        layout.addWidget(self.checkAsmButton)

        self.setLayout(layout)
        return