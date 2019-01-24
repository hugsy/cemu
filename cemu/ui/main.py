import functools
import tempfile
import os
import sys

from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import (
    QApplication,
    qApp,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QMessageBox,
    QAction,
    QFileDialog,
    QGridLayout,
    QLabel,
    QWidget,
    QMainWindow
)

from PyQt5.QtGui import(
    QIcon,
)

from PyQt5.QtCore import(
    QSettings,
    QFileInfo
)

from cemu.utils import (
    list_available_plugins,
    load_plugin,
    assemble,
    disassemble_file
)

import cemu.const

from cemu.emulator import Emulator
from cemu.shortcuts import Shortcut
from cemu.arch import (
    DEFAULT_ARCHITECTURE,
    Architectures,
    get_architecture_by_name,
    Endianness,
    Syntax
)

from cemu.const import (
    COMMENT_MARKER,
    PROPERTY_MARKER,
    WINDOW_SIZE,
    EXAMPLE_PATH,
    TEMPLATE_PATH,
    HOME,
    TITLE,
)

from .codeeditor import CodeWidget
from .mapping import MemoryMappingWidget
from .emulator import EmulatorWidget
from .log import LogWidget
from .command import CommandWidget
from .registers import RegistersWidget
from .memory import MemoryWidget


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
        self.registerWidget = RegistersWidget(self)
        self.memoryViewerWidget = MemoryWidget(self)

        self.runtimeTabWidget = QTabWidget()
        self.runtimeTabWidget.addTab(self.emuWidget, "Emulator")
        self.runtimeTabWidget.addTab(self.logWidget, "Log")
        self.runtimeTabWidget.addTab(self.mapWidget, "Mappings")

        self.AddPluginsToTab(self.runtimeTabWidget) # load additional modules

        runtimeVBoxLayout = QVBoxLayout()
        runtimeVBoxLayout.addWidget(self.memoryViewerWidget)
        runtimeVBoxLayout.addWidget(self.commandWidget)
        runtimeVBoxLayout.addWidget(self.runtimeTabWidget)

        rootLayout = QHBoxLayout()
        rootLayout.addWidget(self.registerWidget, 20)
        rootLayout.addWidget(self.codeWidget, 33)
        rootLayout.addLayout(runtimeVBoxLayout, 47)

        self.setLayout(rootLayout)
        return


    def AddPluginsToTab(self, TabWidget):
        for p in list_available_plugins():
            module = load_plugin(p)
            if not module or not getattr(module, "register"):
                continue

            m = module.register(self)
            if not m:
                continue

            TabWidget.addTab(m, m.title)
            print("Loaded plugin '{}'".format(p))
        return


    def loadContext(self):
        self.emu.reset()
        self.emuWidget.editor.clear()
        maps = self.mapWidget.maps
        if not self.emu.populate_memory(maps):
            return False
        code = self.codeWidget.parser.getCleanCodeAsByte(as_string=False, parse_string=True)
        if not self.emu.compile_code(code):
            return False
        regs = self.registerWidget.getRegisters()
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
        self.registerWidget.updateGrid()
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
        self.registerWidget.updateGrid()
        self.memoryViewerWidget.updateEditor()
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


class CEmuWindow(QMainWindow):
    MaxRecentFiles = 5

    def __init__(self, *args, **kwargs):
        super(CEmuWindow, self).__init__()
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

        for i in range(CEmuWindow.MaxRecentFiles):
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

        for i in range(CEmuWindow.MaxRecentFiles):
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
        qFile, _ = QFileDialog.getOpenFileName(self, title, EXAMPLE_PATH, filter + ";;All files (*.*)")

        if not os.access(qFile, os.R_OK):
            return

        if run_disassembler or qFile.endswith(".raw"):
            body = disassemble_file(qFile, self.arch)
            self.loadFile(qFile, data=body)
        else:
            self.loadFile(qFile)
        return


    def loadCodeText(self):
        return self.loadCode("Open Assembly file", "Assembly files (*.asm *.s)", False)


    def loadCodeBin(self):
        return self.loadCode("Open Raw file", "Raw binary files (*.raw)", True)


    def saveCode(self, title, filter, run_assembler):
        qFile, _ = QFileDialog().getSaveFileName(self, title, HOME, filter=filter + ";;All files (*.*)")
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
        return self.saveCode("Save Assembly Pane As", "Assembly files (*.asm *.s)", False)


    def saveCodeBin(self):
        return self.saveCode("Save Raw Binary Pane As", "Raw binary files (*.raw)", True)


    def saveAsCFile(self):
        template = open(TEMPLATE_PATH+"/template.c", "rb").read()
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
        asm_fmt = open( os.sep.join([TEMPLATE_PATH, "template.asm"]), "rb").read()
        txt = self.canvas.codeWidget.parser.getCleanCodeAsByte(as_string=True)
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
        self.canvas.registerWidget.updateGrid()
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
        templ = open(TEMPLATE_PATH + "/about.html", "r").read()
        desc = templ.format(author=cemu.const.AUTHOR, version=cemu.const.VERSION, project_link=cemu.const.URL, issues_link=cemu.const.ISSUES)
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

        maxRecentFiles = CEmuWindow.MaxRecentFiles

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

