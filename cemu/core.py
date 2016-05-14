# -*- coding: utf-8 -*-

import sys, os, functools
import unicorn

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .arch import Architecture, modes, Mode
from .emulator import Emulator
from .utils import *


WINDOW_SIZE = (1500, 700)
ICON = os.path.dirname(os.path.realpath(__file__)) + "/icon.png"


class CodeWidget(QWidget):
    def __init__(self, *args, **kwargs):
        super(CodeWidget, self).__init__()
        layout = QVBoxLayout()
        label = QLabel("Code")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return

    def getCode(self):
        code = []
        text = self.editor.toPlainText()
        for line in text.split("\n"):
            line = line.strip()
            if len(line)==0: continue
            if line.startswith("#"): continue
            if line.startswith(";"): continue
            code.append(bytes(line, encoding="utf-8"))
        return code


class BinaryWidget(QWidget):
    def __init__(self, *args, **kwargs):
        super(BinaryWidget, self).__init__()
        layout = QVBoxLayout()
        label = QLabel("Raw Binary")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


class MemoryMappingWidget(QWidget):
    def __init__(self, *args, **kwargs):
        super(MemoryMappingWidget, self).__init__()
        layout = QVBoxLayout()
        label = QLabel("Memory Mapping (name   address  size   permission)")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        self.setDefaultMemoryLayout()
        return

    def setDefaultMemoryLayout(self):
        txt = [".text   0x40000   0x1000   READ|EXEC",
               ".data   0x60000   0x1000   READ|WRITE",
               ".stack  0x800000  0x4000   READ|WRITE",
               ".misc   0x1000000 0x1000   ALL"]
        self.editor.insertPlainText("\n".join(txt))
        return

    def getMappings(self):
        maps = []
        lines = self.editor.toPlainText().split("\n")
        for line in lines:
            name, address, size, permission = line.split()
            address = int(address, 0x10)
            size = int(size, 0x10)
            maps.append( [name, address, size, permission] )
        return maps


class EmulatorWidget(QWidget):
     def __init__(self, parent, *args, **kwargs):
        super(EmulatorWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        label = QLabel("Emulation")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setReadOnly(True)
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


class CommandWidget(QWidget):
     def __init__(self, parent, *args, **kwargs):
        super(CommandWidget, self).__init__()
        self.parent = parent
        layout = QHBoxLayout()
        layout.addStretch(1)
        runButton = QPushButton("Run all code")
        runButton.clicked.connect( self.parent.runCode )
        stepiButton = QPushButton("Next instruction")
        stepiButton.clicked.connect( self.parent.stepCode )
        stepoButton = QPushButton("Stop")
        stepiButton.clicked.connect( self.parent.stopCode )
        layout.addWidget(runButton)
        layout.addWidget(stepiButton)
        layout.addWidget(stepoButton)
        self.setLayout(layout)
        return


class RegistersWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(RegistersWidget, self).__init__()
        self.parent = parent
        layout = QGridLayout()
        self.values = QTableWidget(10, 2)
        layout.addWidget(self.values)
        self.setLayout(layout)
        self.updateGrid()
        return

    def updateGrid(self):
        current_mode = self.parent.parent.mode
        registers = current_mode.get_registers()
        self.values.setRowCount(len(registers))
        for i, reg in enumerate(registers):
            name = QTableWidgetItem(reg)
            name.setFlags(Qt.NoItemFlags)
            value = QTableWidgetItem( format_address(0x00, current_mode) )
            value.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.values.setItem(i, 0, name)
            self.values.setItem(i, 1, value)
        return

    def getRegisters(self):
        regs = {}
        current_mode = self.parent.parent.mode
        registers = current_mode.get_registers()
        for i, reg in enumerate(registers):
            name = self.values.item(i, 0).text()
            value = self.values.item(i, 1).text()
            regs[name] = int(value, 16)
        return regs


class MemoryWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(MemoryWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        label = QLabel("Memory viewer")
        self.address = QLineEdit()
        self.address.textChanged.connect( self.updateEditor )
        self.editor = QTextEdit()
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setFont(QFont('Courier', 10))
        self.editor.setReadOnly(True)
        layout.addWidget(label)
        layout.addWidget(self.address)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return

    def updateEditor(self):
        emu = self.parent.parent.emulator
        if emu.vm is None:
            self.editor.setText("VM not running")
            return

        addr = self.address.text()
        if not addr.isdigit():
            return

        try:
            addr = int(addr, 16)
            l = 256
            data = emu.vm.mem_read(addr, l)
        except unicorn.unicorn.UcError:
            self.editor.setText("Cannot read at address %x" % addr)
            return

        text = hexdump(data, base=addr)
        self.editor.setText(text)
        return




class CanvasWidget(QWidget):

    def __init__(self, parent, *args, **kwargs):
        super(CanvasWidget, self).__init__()
        self.parent = parent
        self.setEmulatorWidgetLayout()
        self.show()
        return


    def setEmulatorWidgetLayout(self):
        self.codeWidget = CodeWidget()
        self.binWidget = BinaryWidget()
        self.mapWidget = MemoryMappingWidget(self)
        self.emuWidget = EmulatorWidget(self)
        self.commandWidget = CommandWidget(self)
        self.regWidget = RegistersWidget(self)
        self.memWidget = MemoryWidget(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.codeWidget, "Assembly")
        self.tabs.addTab(self.binWidget, "Binary")
        self.tabs.addTab(self.mapWidget, "Mappings")

        hboxTop = QHBoxLayout()
        hboxTop.addWidget(self.tabs)
        hboxTop.addWidget(self.regWidget)

        hboxBottom = QHBoxLayout()
        hboxBottom.addWidget(self.emuWidget)
        hboxBottom.addWidget(self.memWidget)

        vbox = QVBoxLayout()
        vbox.addLayout(hboxTop)
        vbox.addWidget(self.commandWidget)
        vbox.addLayout(hboxBottom)
        self.setLayout(vbox)
        return


    def stopCode(self):
        emu = self.parent.emulator
        emu.stop()
        return


    def stepCode(self):
        return


    def runCode(self):
        self.emuWidget.editor.clear()
        emu = self.parent.emulator
        if emu.vm is None:
            emu.reinit()
        emu.widget = self.emuWidget
        regs = self.regWidget.getRegisters()
        emu.populate_registers(regs)
        maps = self.mapWidget.getMappings()
        emu.populate_memory(maps)
        code = self.codeWidget.getCode()
        emu.compile_code(code)
        emu.map_code()
        emu.run()
        self.regWidget.updateGrid()
        return



class EmulatorWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(EmulatorWindow, self).__init__()
        self.mode = Mode()
        self.emulator = Emulator(self.mode)
        self.canvas = CanvasWidget(self)
        self.setMainWindowProperty()
        self.setMainWindowMenuBar()
        self.setCentralWidget(self.canvas)
        self.show()
        return


    def setMainWindowProperty(self):
        self.resize(*WINDOW_SIZE)
        self.setFixedSize(*WINDOW_SIZE)
        self.setWindowTitle("Cheapest Emulator Ever")
        self.centerMainWindow()
        qApp.setStyle("Cleanlooks")
        return


    def centerMainWindow(self):
        frameGm = self.frameGeometry()
        screen = QApplication.desktop().screenNumber(QApplication.desktop().cursor().pos())
        centerPoint = QApplication.desktop().screenGeometry(screen).center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())
        return


    def setMainWindowMenuBar(self):
        loadAsmAction = QAction(QIcon(), "Load Assembly", self)
        loadAsmAction.setShortcut("Ctrl+O")
        loadAsmAction.triggered.connect( self.updateCodeText )
        loadAsmAction.setStatusTip("Load an assembly file")

        loadBinAction = QAction(QIcon(), "Load Binary", self)
        loadBinAction.setShortcut("Ctrl+B")
        loadBinAction.triggered.connect( self.updateCodeBin )
        loadBinAction.setStatusTip("Load a raw binary file")

        quitAction = QAction(QIcon(), "Quit", self)
        quitAction.setShortcut("Alt+F4")
        quitAction.triggered.connect(QApplication.quit)
        quitAction.setStatusTip("Exit the application")

        self.statusBar()

        menubar = self.menuBar()
        fileMenu = menubar.addMenu("&File")
        fileMenu.addAction(loadAsmAction)
        fileMenu.addAction(loadBinAction)
        fileMenu.addAction(quitAction)

        archMenu = menubar.addMenu("&Architecture")

        for arch in modes.keys():
            archSubMenu = archMenu.addMenu(arch)
            for idx, title, regs in modes[arch]:
                archAction = QAction(QIcon(), title, self)
                if self.mode.get_id() == idx:
                    archAction.setEnabled(False)
                    self.currentAction = archAction
                else:
                    archAction.setStatusTip("Switch context to architecture: '%s'" % title)
                    archAction.triggered.connect( functools.partial(self.updateMode, idx, archAction) )
                archSubMenu.addAction(archAction)
        return


    def updateCode(self, title, widget):
        qFiles = QFileDialog().getOpenFileName(self, "Open file", os.getenv("HOME"), title)
        qFile = qFiles[0]
        if not os.access(qFile, os.R_OK):
            return
        with open(qFile, 'r') as f:
            widget.insertPlainText( f.read() )

        return


    def updateCodeText(self):
        return self.updateCode("Assembly files (*.asm)", self.canvas.codeWidget.editor)


    def updateCodeBin(self):
        return self.updateCode("Raw binary files (*.bin)", self.canvas.binWidget.editor)
        return


    def updateMode(self, idx, newAction):
        self.currentAction.setEnabled(True)
        self.mode.set_new_mode(idx)
        self.canvas.regWidget.updateGrid()
        newAction.setEnabled(False)
        self.currentAction = newAction
        return


def Cemu():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(ICON))
    emu = EmulatorWindow()
    sys.exit(app.exec_())
