# -*- coding: utf-8 -*-

import binascii
import functools
import os
import sys
import tempfile
import time

import unicorn
from pygments import highlight
from pygments.formatter import Formatter
from pygments.lexers import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

import cemu
from cemu.arch import DEFAULT_ARCHITECTURE, Architectures, get_architecture_by_name
from cemu.emulator import Emulator
from cemu.parser import CodeParser
from cemu.shortcuts import Shortcut
from cemu.utils import *


WINDOW_SIZE = (1600, 800)
PKG_PATH = os.path.dirname(os.path.realpath(__file__))
ICON_PATH = "{}/img/icon.png".format(PKG_PATH)
EXAMPLES_PATH = "{}/examples".format(PKG_PATH)
TEMPLATES_PATH = "{}/templates".format(PKG_PATH)
TITLE = "CEmu - Cheap Emulator v.{}".format(cemu.VERSION)
HOME = os.getenv("HOME")

COMMENT_MARKER = ";;;"
PROPERTY_MARKER = "@@@"

if sys.version_info.major == 3:
    long = int


class QFormatter(Formatter):
    def __init__(self, *args, **kwargs):
        Formatter.__init__(self)
        self.data=[]
        self.styles={}
        for token, style in self.style:
            qtf=QTextCharFormat()
            if style['color']:
                qtf.setForeground(self.hex2QColor(style['color']))
            if style['bgcolor']:
                qtf.setBackground(self.hex2QColor(style['bgcolor']))
            if style['bold']:
                qtf.setFontWeight(QFont.Bold)
            if style['italic']:
                qtf.setFontItalic(True)
            if style['underline']:
                qtf.setFontUnderline(True)
            self.styles[str(token)]=qtf
        return


    def hex2QColor(self, c):
        red = int(c[0:2], 16)
        green = int(c[2:4], 16)
        blue = int(c[4:6], 16)
        return QColor(red, green, blue)


    def format(self, tokensource, outfile):
        self.data=[]
        for ttype, value in tokensource:
            l=len(value)
            t=str(ttype)
            self.data.extend([self.styles[t],]*l)
        return


class Highlighter(QSyntaxHighlighter):
    def __init__(self, parent, mode):
        QSyntaxHighlighter.__init__(self, parent)
        self.tstamp=time.time()
        self.formatter=QFormatter()
        self.lexer=get_lexer_by_name(mode)
        return


    def highlightBlock(self, text):
        cb = self.currentBlock()
        p = cb.position()
        text = self.document().toPlainText() +'\n'
        highlight(text,self.lexer,self.formatter)
        for i in range(len(text)):
            try:
                self.setFormat(i,1,self.formatter.data[p+i])
            except IndexError:
                pass
        self.tstamp = time.time()
        return



class CodeInfoBarWidget(QWidget):
    def __init__(self, textedit_widget, *args, **kwargs):
        super(CodeInfoBarWidget, self).__init__()
        self.textedit_widget = textedit_widget
        self.setFixedHeight(30)
        layout = QHBoxLayout()
        self.label = QLabel("Line:0 Column:0")
        self.label.setFont(QFont("Courier", 11))
        layout.addWidget(self.label)
        self.setLayout(layout)
        # self.textedit_widget.verticalScrollBar().valueChanged.connect(self.UpdateLabel)
        self.textedit_widget.cursorPositionChanged.connect(self.UpdateLabel)
        return


    def UpdateLabel(self):
        pos = self.textedit_widget.textCursor().position()
        text = self.textedit_widget.toPlainText()
        pos_x = text[:pos].count('\n') + 1
        pos_y = len(text[:pos].split('\n')[-1]) + 1
        self.label.setText("Line:{:d} Column:{:d}".format(pos_x, pos_y))
        return


class CodeEdit(QTextEdit):
    def __init__(self):
        super(CodeEdit, self).__init__()
        self.cursorPositionChanged.connect(self.UpdateHighlightedLine)
        return


    def UpdateHighlightedLine(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(QTextFormat.FullWidthSelection, QVariant(True))
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection,])
        return


class CodeEditorFrame(QFrame):
    def __init__(self, *args, **kwargs):
        super(CodeEditorFrame, self).__init__()
        # init code pane
        self.editor = CodeEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        self.highlighter = Highlighter(self.editor, "asm")
        # info bar
        self.infobar = CodeInfoBarWidget(self.editor)
        vbox = QVBoxLayout(self)
        vbox.setSpacing(0)
        vbox.addWidget(self.editor)
        vbox.addWidget(self.infobar)
        return


class CodeWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__()
        self.parent = parent
        self.code_editor_frame = CodeEditorFrame()
        self.editor = self.code_editor_frame.editor
        layout = QVBoxLayout()
        layout.addWidget( QLabel("Code") )
        layout.setSpacing(0)
        layout.addWidget(self.code_editor_frame)
        self.setLayout(layout)
        self.parser = CodeParser(self)
        return



class MemoryMappingWidget(QWidget):
    def __init__(self, *args, **kwargs):
        super(MemoryMappingWidget, self).__init__()
        layout = QVBoxLayout()
        self.title = ["Name", "Base address", "Size", "Permission", "Raw data file"]
        self.memory_mapping = QTableWidget(10, len(self.title))
        self.memory_mapping.setHorizontalHeaderLabels(self.title)
        self.memory_mapping.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.memory_mapping)
        self.setLayout(layout)
        self.populateWithInitialValues()
        return

    def initialMemoryLayout(self):
        return [
            [".text", 0x40000, 0x1000, "READ|EXEC", None],
            [".data", 0x60000, 0x1000, "READ|WRITE", None],
            [".stack", 0x800000, 0x4000, "READ|WRITE", None],
            [".misc", 0x900000, 0x1000, "ALL", None],
        ]

    def populateWithInitialValues(self):
        self._maps = self.initialMemoryLayout()
        for i in range(self.memory_mapping.rowCount()):
            self.memory_mapping.setRowHeight(i, 20)

        for i, mem_map in enumerate(self._maps):
            for j, entry in enumerate(mem_map):
                if isinstance(entry, int): entry = hex(entry)
                elif entry is None: entry = ""
                item = QTableWidgetItem(entry)
                if i in (0, 2):
                    # make sure .text and .stack exist
                    item.setFlags(Qt.ItemIsEnabled)
                else:
                    item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
                self.memory_mapping.setItem(i, j, item)
        return

    def getMappingsFromTable(self):
        self._maps = []
        sz = self.memory_mapping.rowCount()
        for i in range(sz):
            name = self.memory_mapping.item(i, 0)
            if not name:
                continue
            name = name.text()

            address = self.memory_mapping.item(i, 1)
            if address:
                if ishex(address.text()):
                    address = int(address.text(), 0x10)
                else:
                    address = int(address.text())

            size = self.memory_mapping.item(i, 2)
            if size:
                size = int(size.text(), 0x10) if ishex(size.text()) else int(size.text())

            permission = self.memory_mapping.item(i, 3)
            if permission:
                permission = permission.text()

            read_from_file = self.memory_mapping.item(i, 4)
            if read_from_file and not os.access(read_from_file.text(), os.R_OK):
                read_from_file = None

            self._maps.append([name, address, size, permission, read_from_file])
        return

    @property
    def maps(self):
        self.getMappingsFromTable()
        return self._maps



class EmulatorWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(EmulatorWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setReadOnly(True)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


class LogWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(LogWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setReadOnly(True)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


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


class RegistersWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(RegistersWidget, self).__init__()
        self.parent = parent
        self.row_size = 15
        self.old_register_values = {}
        layout = QVBoxLayout()
        label = QLabel("Registers")
        self.values = QTableWidget(10, 2)
        self.values.horizontalHeader().setStretchLastSection(True)
        self.values.setHorizontalHeaderLabels(["Register", "Value"])
        layout.addWidget(label)
        layout.addWidget(self.values)
        self.setLayout(layout)
        self.updateGrid()
        return


    def updateGrid(self):
        emuwin = self.parent.parent
        emu = emuwin.emulator
        current_mode = emuwin.arch
        registers = current_mode.registers
        self.values.setRowCount(len(registers))
        for i, reg in enumerate(registers):
            self.values.setRowHeight(i, self.row_size)
            name = QTableWidgetItem(reg)
            name.setFlags(Qt.NoItemFlags)
            val = emu.get_register_value(reg) if emu.vm else 0
            old_val = self.old_register_values.get(reg, 0)
            if type(val) in (int, long):
                value = format_address(val, current_mode)
            else:
                value = str(val)
            value = QTableWidgetItem( value )
            if old_val != val:
                self.old_register_values[reg] = val
                value.setForeground(QColor(Qt.red))
            value.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.values.setItem(i, 0, name)
            self.values.setItem(i, 1, value)
        return


    def getRegisters(self):
        regs = {}
        current_mode = self.parent.parent.arch
        registers = current_mode.registers
        for i, reg in enumerate(registers):
            name = self.values.item(i, 0).text()
            value = self.values.item(i, 1).text()
            regs[name] = int(value, 16)
        return regs


class ScratchboardWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(ScratchboardWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        label = QLabel("Scratchboard")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.highlighter = Highlighter(self.editor, "rest")
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


class MemoryWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(MemoryWidget, self).__init__()
        self.parent = parent
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Memory viewer"))
        self.address = QLineEdit()
        self.address.textChanged.connect(self.updateEditor)
        title_layout.addWidget(self.address)
        title_widget = QWidget()
        title_widget.setLayout(title_layout)
        title_widget.setMouseTracking(True)

        memview_layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setFont(QFont('Courier', 10))
        self.editor.setReadOnly(True)
        memview_layout.addWidget(title_widget)
        memview_layout.addWidget(self.editor)
        self.setLayout(memview_layout)
        return

    def enterEvent(self, evt):
        return

    def leaveEvent(self, evt):
        return

    def mouseMoveEvent(self, evt):
        return

    def updateEditor(self):
        emu = self.parent.parent.emulator
        if emu.vm is None:
            self.editor.setText("VM not running")
            return

        value = self.address.text()
        if value.startswith("0x") or value.startswith("0X"):
            value = value[2:]

        if value.startswith("@"):
            # if the value of the "memory viewer" field starts with @.<section_name>
            addr = emu.lookup_map(value[1:])
            if addr is None:
                return

        elif value.startswith("$"):
            # if the value of the "memory viewer" field starts with $<register_name>
            reg_name = value[1:].upper()
            if reg_name not in emu.arch.registers:
                return
            addr = emu.get_register_value(reg_name)
            if addr is None:
                return

        else:
            if not value.isdigit():
                return
            addr = int(value, 16)

        try:
            l = 256
            data = emu.vm.mem_read(addr, l)
            text = hexdump(data, base=addr)
            self.editor.setText(text)
        except unicorn.unicorn.UcError:
            self.editor.setText("Cannot read at address %x" % addr)

        return


class CanvasWidget(QWidget):

    def __init__(self, parent, *args, **kwargs):
        super(CanvasWidget, self).__init__()
        self.parent = parent
        self.emu = self.parent.emulator
        self.emu.widget = self
        self.setCanvasWidgetLayout()
        self.commandWidget.stopButton.setDisabled(True)
        self.show()
        return


    def setCanvasWidgetLayout(self):
        self.codeWidget = CodeWidget(self)
        self.mapWidget = MemoryMappingWidget(self)
        self.emuWidget = EmulatorWidget(self)
        self.logWidget = LogWidget(self)
        self.commandWidget = CommandWidget(self)
        self.regWidget = RegistersWidget(self)
        self.memWidget = MemoryWidget(self)
        self.scratchWidget = ScratchboardWidget(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.codeWidget, "Assembly")
        self.tabs.addTab(self.mapWidget, "Mappings")

        hboxTop2 = QHBoxLayout()
        hboxTop2.addWidget(self.regWidget)
        hboxTop2.addWidget(self.scratchWidget)

        hboxTop = QHBoxLayout()
        hboxTop.addWidget(self.tabs)
        hboxTop.addLayout(hboxTop2)

        self.tabs2 = QTabWidget()
        self.tabs2.addTab(self.emuWidget, "Emulator")
        self.tabs2.addTab(self.logWidget, "Log")

        # load additional modules
        for p in list_available_plugins():
            module = load_plugin(p)
            if not getattr(module, "register"):
                continue

            m = module.register(self)
            if not m:
                continue

            self.tabs2.addTab(m, m.title)
            print("Loaded plugin '{}'".format(p))

        hboxBottom = QHBoxLayout()
        hboxBottom.addWidget(self.tabs2)
        hboxBottom.addWidget(self.memWidget)

        vbox = QVBoxLayout()
        vbox.addLayout(hboxTop)
        vbox.addWidget(self.commandWidget)
        vbox.addLayout(hboxBottom)
        self.setLayout(vbox)
        return


    def loadContext(self):
        self.emu.reinit()
        self.emuWidget.editor.clear()
        maps = self.mapWidget.maps
        if not self.emu.populate_memory(maps):
            return False
        code = self.codeWidget.parser.getCleanCodeAsByte(as_string=False, parse_string=True)
        if not self.emu.compile_code(code):
            return False
        regs = self.regWidget.getRegisters()
        if not self.emu.populate_registers(regs):
            return False
        if not self.emu.map_code():
            return False
        return True


    def stopCode(self):
        if not self.emu.is_running:
            self.emu.log("No emulation context loaded.")
            return
        self.emu.stop()
        self.regWidget.updateGrid()
        self.emu.log("Emulation context reset")
        self.commandWidget.stopButton.setDisabled(True)
        self.commandWidget.runButton.setDisabled(False)
        self.commandWidget.stepButton.setDisabled(False)
        return


    def stepCode(self):
        self.emu.use_step_mode = True
        self.emu.stop_now = False
        self.run()
        return


    def runCode(self):
        self.emu.use_step_mode = False
        self.emu.stop_now = False
        self.run()
        return


    def run(self):
        if not self.emu.is_running:
            if not self.loadContext():
                self.logWidget.editor.append("An error occured when loading context")
                return
            self.emu.is_running = True
            self.commandWidget.stopButton.setDisabled(False)

        self.emu.run()
        self.regWidget.updateGrid()
        self.memWidget.updateEditor()
        return


    def checkAsmCode(self):
        code = self.codeWidget.parser.getCleanCodeAsByte()
        if self.emu.compile_code(code, False):
            msg = "Your code is syntaxically valid."
            popup = QMessageBox.information
        else:
            msg = "Some errors were found in your code, check the logs..."
            popup = QMessageBox.warning

        popup(self,"Checking assembly code syntax...", msg)
        return


class EmulatorWindow(QMainWindow):
    MaxRecentFiles = 5

    def __init__(self, *args, **kwargs):
        super(EmulatorWindow, self).__init__()
        self.arch = DEFAULT_ARCHITECTURE
        self.recentFileActions = []
        self.archActions = {}
        self.current_file = None
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.shortcuts = Shortcut()
        self.emulator = Emulator(self)
        self.canvas = CanvasWidget(self)
        self.setMainWindowProperty()
        self.setMainWindowMenuBar()
        self.setCentralWidget(self.canvas)
        self.show()
        return


    def setMainWindowProperty(self):
        self.resize(*WINDOW_SIZE)
        self.updateTitle()
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


    def add_menu_item(self, title, callback, description=None, shortcut=None):
        action = QAction(QIcon(), title, self)
        action.triggered.connect( callback )
        if description:
            action.setStatusTip(description)
        if shortcut:
            action.setShortcut(shortcut)
        return action


    def setMainWindowMenuBar(self):
        self.statusBar()
        menubar = self.menuBar()

        # Add File menu bar
        fileMenu = menubar.addMenu("&File")

        loadAsmAction = self.add_menu_item("Load Assembly", self.loadCodeText,
                                           self.shortcuts.description("load_assembly"),
                                           self.shortcuts.shortcut("load_assembly"))

        loadBinAction = self.add_menu_item("Load Binary", self.loadCodeBin,
                                           self.shortcuts.description("load_binary"),
                                           self.shortcuts.shortcut("load_binary"))

        for i in range(EmulatorWindow.MaxRecentFiles):
            self.recentFileActions.append(QAction(self, visible=False, triggered=self.openRecentFile))

        clearRecentFilesAction = self.add_menu_item("Clear Recent Files", self.clearRecentFiles,
                                                    "Clear Recent Files", "")

        saveAsmAction = self.add_menu_item("Save Assembly", self.saveCodeText,
                                           self.shortcuts.description("save_as_asm"),
                                           self.shortcuts.shortcut("save_as_asm"))

        saveBinAction = self.add_menu_item ("Save Binary", self.saveCodeBin,
                                            self.shortcuts.description("save_as_binary"),
                                            self.shortcuts.shortcut("save_as_binary"))

        saveCAction = self.add_menu_item("Generate C code", self.saveAsCFile,
                                         self.shortcuts.description("generate_c_file"),
                                         self.shortcuts.shortcut("generate_c_file"))

        saveAsAsmAction = self.add_menu_item("Generate Assembly code", self.saveAsAsmFile,
                                             self.shortcuts.description("generate_asm_file"),
                                             self.shortcuts.shortcut("generate_asm_file"))

        quitAction = self.add_menu_item("Quit", QApplication.quit,
                                        self.shortcuts.shortcut("exit_application"),
                                        self.shortcuts.description("exit_application"))

        fileMenu.addAction(loadAsmAction)
        fileMenu.addAction(loadBinAction)
        fileMenu.addSeparator()

        for i in range(EmulatorWindow.MaxRecentFiles):
            fileMenu.addAction(self.recentFileActions[i])
        self.updateRecentFileActions()
        fileMenu.addSeparator()

        fileMenu.addAction(clearRecentFilesAction)
        fileMenu.addSeparator()

        fileMenu.addAction(saveAsmAction)
        fileMenu.addAction(saveBinAction)
        fileMenu.addAction(saveCAction)
        fileMenu.addAction(saveAsAsmAction)
        fileMenu.addSeparator()

        fileMenu.addAction(quitAction)

        # Add Architecture menu bar
        archMenu = menubar.addMenu("&Architecture")
        for abi in sorted(Architectures.keys()):
            archSubMenu = archMenu.addMenu(abi)
            for arch in Architectures[abi]:
                self.archActions[arch.name] = QAction(QIcon(), str(arch), self)
                if arch == self.arch:
                    self.archActions[arch.name].setEnabled(False)
                    self.currentAction = self.archActions[arch.name]

                self.archActions[arch.name].setStatusTip("Switch context to architecture: '%s'" % arch)
                self.archActions[arch.name].triggered.connect( functools.partial(self.updateMode, arch) )
                archSubMenu.addAction(self.archActions[arch.name])

        # Add Help menu bar
        helpMenu = menubar.addMenu("&Help")
        shortcutAction = self.add_menu_item("Shortcuts", self.showShortcutPopup,
                                            self.shortcuts.description("shortcut_popup"),
                                            self.shortcuts.shortcut("shortcut_popup"))

        aboutAction = self.add_menu_item("About", self.showAboutPopup,
                                         self.shortcuts.description("about_popup"))

        helpMenu.addAction(shortcutAction)
        helpMenu.addAction(aboutAction)
        return


    def loadFile(self, fname, data=None):

        if data is None:
            data = open(fname, 'r').read()

        for line in data.splitlines():
            part = line.strip().split()
            if len(part) < 3:
                continue

            if not (part[0] == COMMENT_MARKER and part[1] == PROPERTY_MARKER):
                continue

            if part[2].startswith("arch:"):
                try:
                    arch_from_file = part[2][5:]
                    arch = get_architecture_by_name(arch_from_file)
                    self.updateMode(arch)
                except KeyError:
                    self.canvas.logWidget.editor.append("Unknown architecture '{:s}', discarding...".format(arch_from_file))
                    continue

            if part[2].startswith("endian:"):
                endian_from_file = part[2][7:].lower()
                if endian_from_file not in ("little", "big"):
                    self.canvas.logWidget.editor.append("Incorrect endianness '{:s}', discarding...".format(endian_from_file))
                    continue
                self.arch.endianness = Endianness.LITTLE if endian_from_file == "little" else Endianness.BIG
                self.canvas.logWidget.editor.append("Changed endianness to '{:s}'".format(endian_from_file))

            if part[2].startswith("syntax:"):
                syntax_from_file = part[2][7:].lower()
                if syntax_from_file not in ("att", "intel"):
                    self.canvas.logWidget.editor.append("Incorrect syntax '{:s}', discarding...".format(syntax_from_file))
                    continue
                self.arch.syntax = Syntax.ATT if syntax_from_file=="att" else Syntax.INTEL
                self.canvas.logWidget.editor.append("Changed syntax to '{:s}'".format(syntax_from_file))


        self.canvas.codeWidget.editor.setPlainText(data)
        self.canvas.logWidget.editor.append("Loaded '%s'" % fname)
        self.updateRecentFileActions(fname)
        self.current_file = fname
        self.updateTitle(self.current_file)
        return

    def openRecentFile(self):
        action = self.sender()
        if action:
            self.loadFile(action.data())
        return

    def loadCode(self, title, filter, run_disassembler):
        qFile, qFilter = QFileDialog.getOpenFileName(self, title, EXAMPLES_PATH, filter)

        if not os.access(qFile, os.R_OK):
            return

        if run_disassembler or qFile.endswith(".raw"):
            body = disassemble_file(qFile, self.arch)
            self.loadFile(qFile, data=body)
        else:
            self.loadFile(qFile)
        return


    def loadCodeText(self):
        return self.loadCode("Open Assembly file", "Assembly files (*.asm)", False)


    def loadCodeBin(self):
        return self.loadCode("Open Raw file", "Raw binary files (*.raw)", True)


    def saveCode(self, title, filter, run_assembler):
        qFile, qFilter = QFileDialog().getSaveFileName(self, title, HOME, filter=filter)
        if qFile is None or len(qFile)==0 or qFile=="":
            return

        if run_assembler:
            asm = self.canvas.codeWidget.parser.getCleanCodeAsByte(as_string=True)
            txt, cnt = assemble(asm, self.arch)
            if cnt < 0:
                self.canvas.logWidget.editor.append("Failed to compile: error at line {:d}".format(-cnt))
                return
        else:
            txt = self.canvas.codeWidget.parser.getCleanCodeAsByte(as_string=True)

        with open(qFile, "wb") as f:
            f.write(txt)

        self.canvas.logWidget.editor.append("Saved as '%s'" % qFile)
        return


    def saveCodeText(self):
        return self.saveCode("Save Assembly Pane As", "*.asm", False)


    def saveCodeBin(self):
        return self.saveCode("Save Raw Binary Pane As", "*.raw", True)


    def saveAsCFile(self):
        template = open(TEMPLATES_PATH+"/template.c", "rb").read()
        insns = self.canvas.codeWidget.parser.getCleanCodeAsByte(as_string=False)
        if sys.version_info.major == 2:
            title = bytes(self.arch.name)
        else:
            title = bytes(self.arch.name, encoding="utf-8")

        sc = b'""\n'
        i = 0
        for insn in insns:
            txt, cnt = assemble(insn, self.arch)
            if cnt < 0:
                self.canvas.logWidget.editor.append("Failed to compile: error at line {:d}".format(-cnt))
                return

            c = b'"' + b''.join([ b'\\x%.2x'%txt[i] for i in range(len(txt)) ]) + b'"'
            c = c.ljust(60, b' ')
            c+= b'// ' + insn + b'\n'
            sc += b'\t' + c
            i += len(txt)

        sc += b'\t""'

        body = template % (title, i, sc)
        fd, fpath = tempfile.mkstemp(suffix=".c")
        os.write(fd, body)
        os.close(fd)
        self.canvas.logWidget.editor.append("Saved as '%s'" % fpath)
        return


    def saveAsAsmFile(self):
        asm_fmt = open(TEMPLATES_PATH + "/template.asm", "rb").read()
        txt = self.canvas.codeWidget.parser.getCleanCodeAsByte(as_string=True)
        if sys.version_info.major == 2:
            title = bytes(self.arch.name)
        else:
            title = bytes(self.arch.name, encoding="utf-8")

        asm = asm_fmt % (title, b'\n'.join([b"\t%s"%x for x in txt.split(b'\n')]))
        fd, fpath = tempfile.mkstemp(suffix=".asm")
        os.write(fd, asm)
        os.close(fd)
        self.canvas.logWidget.editor.append("Saved as '%s'" % fpath)


    def updateMode(self, arch):
        self.currentAction.setEnabled(True)
        self.arch = arch
        print("Switching to '%s'" % self.arch)
        self.canvas.logWidget.editor.append("Switching to '%s'" % self.arch)
        self.canvas.regWidget.updateGrid()
        self.archActions[arch.name].setEnabled(False)
        self.currentAction = self.archActions[arch.name]
        self.updateTitle()
        return


    def updateTitle(self, msg=None):
        title = "{} ({})".format(TITLE, self.arch)
        if msg:
            title+=": {}".format(msg)
        self.setWindowTitle(title)
        return


    def showShortcutPopup(self):
        msgbox = QMessageBox(self)
        msgbox.setWindowTitle("CEMU Shortcuts")

        wid = QWidget()
        grid = QGridLayout()
        for j, title in enumerate(["Shortcut", "Description"]):
            lbl = QLabel()
            lbl.setTextFormat(Qt.RichText)
            lbl.setText("<b>{}</b>".format(title))
            grid.addWidget(lbl, 0, j)

        for i, config_item in enumerate(self.shortcuts._config):
            sc, desc = self.shortcuts._config[config_item]
            if not sc:
                continue
            grid.addWidget(QLabel(sc), i+1, 0)
            grid.addWidget(QLabel(desc), i+1, 1)

        wid.setMinimumWidth(800)
        wid.setLayout(grid)
        msgbox.layout().addWidget(wid)
        msgbox.exec_()
        return

    def showAboutPopup(self):
        templ = open(TEMPLATES_PATH + "/about.html", "r").read()
        desc = templ.format(author=cemu.AUTHOR, version=cemu.VERSION, project_link=cemu.LINK, issues_link=cemu.ISSUES)
        msgbox = QMessageBox(self)
        msgbox.setIcon(QMessageBox.Information)
        msgbox.setWindowTitle("About CEMU")
        msgbox.setTextFormat(Qt.RichText)
        msgbox.setText(desc)
        msgbox.setStandardButtons(QMessageBox.Ok)
        msgbox.exec_()
        return

    def updateRecentFileActions(self, insert_file=None):
        settings = QSettings('Cemu', 'Recent Files')
        files = settings.value('recentFileList')
        if files is None:
            # if setting doesn't exist, create it
            settings.setValue('recentFileList', [])
            files = settings.value('recentFileList')

        maxRecentFiles = EmulatorWindow.MaxRecentFiles

        if insert_file:
            # insert new file to list
            if insert_file not in files:
                files.insert(0, insert_file)
            # ensure list size
            if len(files) > maxRecentFiles:
                files = files[0:maxRecentFiles]
            # save the setting
            settings.setValue('recentFileList', files)

        numRecentFiles = min(len(files), maxRecentFiles)

        for i in range(numRecentFiles):
            text = "&%d %s" % (i + 1, self.strippedName(files[i]))
            self.recentFileActions[i].setText(text)
            self.recentFileActions[i].setData(files[i])
            self.recentFileActions[i].setVisible(True)

        for j in range(numRecentFiles, maxRecentFiles):
            self.recentFileActions[j].setVisible(False)
        return

    def strippedName(self, fullFileName):
        return QFileInfo(fullFileName).fileName()

    def clearRecentFiles(self):
        settings = QSettings('Cemu', 'Recent Files')
        settings.setValue('recentFileList', [])
        self.updateRecentFileActions()
        return


def Cemu():
    app = QApplication(sys.argv)
    style = """
    QMainWindow, QWidget{
    background-color: darkgray;
    }

    QTextEdit, QLineEdit, QTableWidget{
    background-color: white;
    }
    """
    app.setStyleSheet(style)
    app.setWindowIcon(QIcon(ICON_PATH))
    emu = EmulatorWindow()
    sys.exit(app.exec_())
