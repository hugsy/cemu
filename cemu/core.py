# -*- coding: utf-8 -*-

import sys
import os
import functools
import time
import tempfile
import binascii

import unicorn

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from pygments import highlight
from pygments.lexers import *
from pygments.formatter import Formatter


from .arch import Architecture, modes, Mode
from .emulator import Emulator
from .reil import Reil
from .utils import *
from .shortcuts import Shortcut
from .console import PythonConsole


WINDOW_SIZE = (1600, 800)
ICON = os.path.dirname(os.path.realpath(__file__)) + "/icon.png"
TITLE = "CEMU - Cheap EMUlator"

if sys.version_info.major == 3:
    long = int


class QFormatter(Formatter):
    # from http://ralsina.me/static/highlighter.py
    # todo: improve
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
        r=int(c[0:2],16)
        g=int(c[2:4],16)
        b=int(c[4:6],16)
        return QColor(r,g,b)


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


class CodeWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__()
        layout = QVBoxLayout()
        label = QLabel("Code")
        self.parent = parent
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.highlighter = Highlighter(self.editor, "asm")
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


    def getCleanCodeAsByte(self, as_string=False, parse_string=True):
        """
        Returns the content of the Code widget as a byte array.
        """
        code = self.editor.toPlainText()
        if code is None or len(code)==0:
            return [] if not as_string else b""

        code = code.split("\n")
        if sys.version_info.major == 2:
            code = [bytes(x) for x in code]
        else:
            code = [bytes(x, encoding="utf-8") for x in code]

        # remove comments
        code = self.getCleanCode(code)

        # parse strings
        if parse_string:
            code = self.parseStringInCode(code)

        if as_string:
            return b'\n'.join(code)

        return code


    def getCleanCode(self, code, as_string=False):
        """
        Returns the code pane content cleaned of all comments.
        """
        comment_tags = ["#", ";", "--",]
        clean = []
        for line in code:
            line = line.strip()
            if len(line)==0:
                continue
            c = line[0]
            if sys.version_info.major == 3:
                c = chr(line[0])
            if c in comment_tags:
                continue
            clean.append(line)

        if as_string:
            return b"\n".join(clean)

        return clean


    def parseStringInCode(self, code, as_string=False):
        """
        This function will search for every line of assembly for quote(")
        pattern and convert it as a hexadecimal number.
        """
        parsed = []
        for line in code:
            i = line.find(b'"')
            if i==-1:
                # no string
                parsed.append(line)
                continue

            j = line[i+1:].find(b'"')
            if j==-1:
                # unfinished string
                parsed.append(line)
                continue

            if (j*8) != self.parent.parent.emulator.mode.get_memory_alignment():
                # incorrect size
                parsed.append(line)
                continue

            origstr = line[i+1:i+j+1]
            hexstr  = binascii.hexlify(origstr)
            newline = line.replace(b'"%s"'%origstr, b'0x%s'%hexstr)
            parsed.append(newline)

        if as_string:
            return b'\n'.join(parsed)

        return parsed


class MemoryMappingWidget(QWidget):
    def __init__(self, *args, **kwargs):
        super(MemoryMappingWidget, self).__init__()
        layout = QVBoxLayout()
        label = QLabel("Memory Mapping (name   address  size   permission   [input_file])")
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
            line = line.strip()
            if line.startswith("#"):
                continue

            parts = line.split()
            read_from_file = None
            if len(parts)==5:
                read_from_file = parts[4]

            name, address, size, permission = parts[0:4]
            address = int(address, 0x10)
            size = int(size, 0x10)
            maps.append( [name, address, size, permission, read_from_file] )
        return maps


class SymR(QWidget):
     def __init__(self, parent, *args, **kwargs):
        super(SymR, self).__init__()
        self.parent = parent
        self.symr = self.parent.symr
        layout = QVBoxLayout()
        label = QLabel("OpenREIL context")
        self.editor = QTextEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setReadOnly(True)
        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)
        return


class PythonConsoleWidget(QWidget):
     def __init__(self, parent, *args, **kwargs):
        super(PythonConsoleWidget, self).__init__()
        self.parent = parent
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Python Interpreter"))
        console = PythonConsole(startup_message="[+] Welcome to Python in CEMU", parent=self)
        highlighter = Highlighter(console, "py")
        layout.addWidget(console)
        self.setLayout(layout)
        return


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
        label = QLabel("Log")
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
        sc = self.parent.parent.shortcuts
        layout = QHBoxLayout()
        layout.addStretch(1)

        self.runButton = QPushButton("Run all code")
        self.runButton.clicked.connect( self.parent.runCode )
        self.runButton.setShortcut(sc.shortcut("emulator_run_all"))

        self.stepButton = QPushButton("Next instruction")
        self.stepButton.clicked.connect( self.parent.stepCode )
        self.stepButton.setShortcut(sc.shortcut("emulator_step"))

        self.stopButton = QPushButton("Stop")
        self.stopButton.setShortcut(sc.shortcut("emulator_stop"))
        self.stopButton.clicked.connect( self.parent.stopCode )

        self.checkAsmButton = QPushButton("Check assembly code")
        self.checkAsmButton.setShortcut(sc.shortcut("emulator_check"))
        self.checkAsmButton.clicked.connect( self.parent.checkAsmCode )

        layout.addWidget(self.runButton)
        layout.addWidget(self.stepButton)
        layout.addWidget(self.stopButton)
        layout.addWidget(self.checkAsmButton)

        if self.parent.parent.reil.reiluse:
            self.symButton = QPushButton("Symbolic expressions")
            self.symButton.clicked.connect( self.parent.SymCode)
            layout.addWidget(self.symButton)

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
        emu = self.parent.parent.emulator
        current_mode = self.parent.parent.mode
        registers = current_mode.get_registers()
        self.values.setRowCount(len(registers))
        for i, reg in enumerate(registers):
            self.values.setRowHeight(i, self.row_size)
            name = QTableWidgetItem(reg)
            name.setFlags(Qt.NoItemFlags)
            if emu.vm is None:
                val = 0
            else:
                val = emu.get_register_value(reg)
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
        current_mode = self.parent.parent.mode
        registers = current_mode.get_registers()
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
        self.address.textChanged.connect( self.updateEditor )
        title_layout.addWidget(self.address)
        title_widget = QWidget()
        title_widget.setLayout(title_layout)

        memview_layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setFont(QFont('Courier', 10))
        self.editor.setReadOnly(True)
        memview_layout.addWidget(title_widget)
        memview_layout.addWidget(self.editor)
        self.setLayout(memview_layout)
        return

    def updateEditor(self):
        emu = self.parent.parent.emulator
        if emu.vm is None:
            self.editor.setText("VM not running")
            return

        addr = self.address.text()
        if addr.startswith("0x") or addr.startswith("0X"):
            addr = addr[2:]

        if addr.startswith("@"):
            addr = emu.lookup_map(addr[1:])
            if addr is None:
                return
        else:
            if not addr.isdigit():
                return
            addr = int(addr, 16)

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
        self.symr = self.parent.reil
        self.symr.widget = self
        self.setCanvasWidgetLayout()
        self.commandWidget.stopButton.setDisabled(True)
        self.show()
        return


    def setCanvasWidgetLayout(self):
        self.codeWidget = CodeWidget(self)
        self.mapWidget = MemoryMappingWidget(self)
        self.emuWidget = EmulatorWidget(self)
        self.logWidget = LogWidget(self)
        self.consoleWidget = PythonConsoleWidget(self)
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
        self.tabs2.addTab(self.consoleWidget, "Python")
        if self.parent.reil.reiluse:
            self.Symrwidget = SymR(self)
            self.tabs2.addTab(self.Symrwidget, "IR Context")

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
        maps = self.mapWidget.getMappings()
        if not self.emu.populate_memory(maps):
            return False
        code = self.codeWidget.getCleanCodeAsByte(as_string=False, parse_string=True)
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

    def SymCode(self):
        if sys.version_info[:2] > (2, 7):
            self.Symrwidget.editor.append("Must use Python 2.x")
            return

        self.commandWidget.stopButton.setDisabled(False)
        self.symr.entry()
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
        code = self.codeWidget.getCleanCodeAsByte()
        if self.emu.compile_code(code, False):
            msg = "Your code is syntaxically valid."
            popup = QMessageBox.information
        else:
            msg = "Some errors were found in your code, please check..."
            popup = QMessageBox.warning

        popup(self,"Checking assembly code syntax...", msg)
        return


class EmulatorWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(EmulatorWindow, self).__init__()
        self.mode = Mode()
        self.shortcuts = Shortcut()
        self.emulator = Emulator(self.mode)
        self.reil = Reil(self.mode)
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
        fileMenu.addAction(saveAsmAction)
        fileMenu.addAction(saveBinAction)
        fileMenu.addAction(saveCAction)
        fileMenu.addAction(saveAsAsmAction)
        fileMenu.addAction(quitAction)

        # Add Architecture menu bar
        archMenu = menubar.addMenu("&Architecture")
        for arch in modes.keys():
            archSubMenu = archMenu.addMenu(arch)
            for idx, title, _, _, _ in modes[arch]:
                archAction = QAction(QIcon(), title, self)
                if self.mode.get_id() == idx:
                    archAction.setEnabled(False)
                    self.currentAction = archAction

                archAction.setStatusTip("Switch context to architecture: '%s'" % title)
                archAction.triggered.connect( functools.partial(self.updateMode, idx, archAction) )
                archSubMenu.addAction(archAction)

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


    def loadCode(self, title, filter, run_disassembler):
        qFile, qFilter = QFileDialog().getOpenFileName(self, title, ".", filter)

        if not os.access(qFile, os.R_OK):
            return

        if run_disassembler:
            body = disassemble_file(qFile, self.mode)
        else:
            with open(qFile, 'r') as f:
                body = f.read()

        self.canvas.codeWidget.editor.setPlainText( body )
        self.canvas.logWidget.editor.append("Loaded '%s'" % qFile)
        return


    def loadCodeText(self):
        return self.loadCode("Open Assembly file", "Assembly files (*.asm)", False)


    def loadCodeBin(self):
        return self.loadCode("Open Raw file", "Raw binary files (*.raw)", True)


    def saveCode(self, title, filter, run_assembler):
        qFile, qFilter = QFileDialog().getSaveFileName(self, title, ".", filter=filter)
        if qFile is None or len(qFile)==0 or qFile=="":
            return

        if run_assembler:
            asm = self.canvas.codeWidget.getCleanCodeAsByte(as_string=True)
            txt, cnt = assemble(asm, self.mode)
            if cnt < 0:
                self.canvas.logWidget.editor.append("Failed to compile code")
                return
        else:
            txt = self.canvas.codeWidget.getCleanCodeAsByte(as_string=True)

        with open(qFile, "wb") as f:
            f.write(txt)

        self.canvas.logWidget.editor.append("Saved as '%s'" % qFile)
        return


    def saveCodeText(self):
        return self.saveCode("Save Assembly Pane As", "*.asm", False)


    def saveCodeBin(self):
        return self.saveCode("Save Raw Binary Pane As", "*.raw", True)


    def saveAsCFile(self):

        template = b"""/**
 * Generated by cemu
 *
 * Architecture: %s
 *
 */

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define LEN %d

const char sc[LEN] = %s;

void trigger()
{
    void *sc_mapped;
    void (*func)();
    sc_mapped = mmap(NULL, LEN, PROT_READ|PROT_EXEC|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
    memcpy(sc_mapped, sc, LEN);
    func = (void (*)()) sc_mapped;
    (*func)();
    munmap(sc_mapped, LEN);
    return;
}


int main(int argc, char** argv, char** envp)
{
    trigger();
    return 0;
}
"""
        insns = self.canvas.codeWidget.getCleanCodeAsByte(as_string=False)
        if sys.version_info.major == 2:
            title = bytes(self.mode.get_title())
        else:
            title = bytes(self.mode.get_title(), encoding="utf-8")

        sc = b'""\n'
        i = 0
        for insn in insns:
            txt, cnt = assemble(insn, self.mode)
            if cnt < 0:
                self.canvas.logWidget.editor.append("Failed to compile code")
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
        asm_fmt = b""";;;
;;; Generated by cemu
;;;
;;; Architecture: %s
;;;

        global  _start

        section .text

_start:
%s

;;;
;;;
;;; End of code
;;;
;;;
"""
        txt = self.canvas.codeWidget.getCleanCodeAsByte(as_string=True)
        if sys.version_info.major == 2:
            title = bytes(self.mode.get_title())
        else:
            title = bytes(self.mode.get_title(), encoding="utf-8")

        asm = asm_fmt % (title, b'\n'.join([b"\t%s"%x for x in txt.split(b'\n')]))
        fd, fpath = tempfile.mkstemp(suffix=".asm")
        os.write(fd, asm)
        os.close(fd)
        self.canvas.logWidget.editor.append("Saved as '%s'" % fpath)


    def updateMode(self, idx, newAction):
        self.currentAction.setEnabled(True)
        self.mode.set_new_mode(idx)
        self.canvas.regWidget.updateGrid()
        newAction.setEnabled(False)
        self.currentAction = newAction
        self.updateTitle()
        return


    def updateTitle(self):
        self.setWindowTitle("{} ({})".format(TITLE, self.mode.get_title()))
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
        msgbox.exec()
        return

    def showAboutPopup(self):
        desc = \
"""
<b>CEMU</b>: Cheap EMUlator
<br>
Created and maintained by @_hugsy_ (<a href="https://github.com/hugsy/cemu">Link on GitHub</a>)
<br>
<br>
CEMU allows you to play easily with assembly on many architectures (x86, ARM, MIPS, etc.),
compile execute the result in an emulated environment.
<br>
It is a perfect tool to learn assembly, load raw binary dumps captured, or build your custom
shellcodes.
<br>
<br>
The software is distributed freely under the MIT license.
This tool relies on the fantastic libraries/framworks:
<br>
<ul>
<li><a href="http://www.keystone-engine.org/">Keystone</a></li>
<li><a href="http://www.capstone-engine.org/">Capstone</a></li>
<li><a href="http://www.unicorn-engine.org/">Unicorn</a></li>
<li><a href="http://pygments.org/">Pygments</a></li>
<li><a href="https://www.riverbankcomputing.com/software/pyqt/">PyQt5</a></li>
</ul>
<br>
<br>
For issues, please send detailed reports <a href="https://github.com/hugsy/cemu/issues">here</a> <br>
<br>
Thanks for using <b>CEMU</b>.
<br>
<br>
<i>hugsy</i>
<br>
<a href="https://twitter.com/_hugsy_">Twitter</a>
<br>
<a href="https://github.com/hugsy">GitHub</a>
"""
        msgbox = QMessageBox(self)
        msgbox.setIcon(QMessageBox.Information)
        msgbox.setWindowTitle("About CEMU")
        msgbox.setTextFormat(Qt.RichText)
        msgbox.setText(desc)
        msgbox.setStandardButtons(QMessageBox.Ok)
        msgbox.exec()
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
    app.setWindowIcon(QIcon(ICON))
    emu = EmulatorWindow()
    # emu.setWindowFlags(QtCore.Qt.FramelessWindowHint)
    # emu.show()
    sys.exit(app.exec_())
