import functools
import os
import tempfile
from typing import Callable, Optional

from PyQt6.QtCore import QFileInfo, QSettings, Qt
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (QApplication, QDockWidget, QFileDialog,
                             QGridLayout, QLabel, QMainWindow, QMenu,
                             QMessageBox, QWidget)

from ..arch import (Architecture, Architectures, Endianness, Syntax,
                    get_architecture_by_name, load_architectures)
from ..const import (AUTHOR, COMMENT_MARKER, CONFIG_FILEPATH, EXAMPLE_PATH,
                     HOME, ISSUE_LINK, PROPERTY_MARKER, TEMPLATE_PATH, TITLE,
                     URL, VERSION)
from ..emulator import Emulator
from ..exports import build_elf_executable, build_pe_executable
from ..memory import MemorySection
from ..settings import Settings
from ..shortcuts import Shortcut
from ..utils import (assemble, disassemble_file, list_available_plugins,
                     load_plugin)
from .codeeditor import CodeWidget
from .command import CommandWidget
from .log import LogWidget
from .mapping import MemoryMappingWidget
from .memory import MemoryWidget
from .registers import RegistersWidget

from cemu.log import ok, info, warn, error


class CEmuWindow(QMainWindow):

    def __init__(self, app: QApplication, *args, **kwargs):
        super(CEmuWindow, self).__init__()
        self.__app = app
        self.settings = Settings()
        load_architectures()
        self.arch = get_architecture_by_name(
            self.settings.get("Global", "DefaultArchitecture", "x86_64"))
        self.recentFileActions = []
        self.__plugins: list[QDockWidget] = []
        self.__dockable_widgets = []
        self.archActions = {}
        self.signals = {}
        self.current_file = None

        self.shortcuts = Shortcut()
        self.shortcuts.load_from_settings(self.settings)

        # prepare the emulator
        self.emulator = Emulator(self)

        # set up the dockable items
        self.__regsWidget = RegistersWidget(self)
        self.__dockable_widgets.append(self.__regsWidget)
        self.__mapWidget = MemoryMappingWidget(self)
        self.__dockable_widgets.append(self.__mapWidget)
        self.__memWidget = MemoryWidget(self)
        self.__dockable_widgets.append(self.__memWidget)
        self.__cmdWidget = CommandWidget(self)
        self.__dockable_widgets.append(self.__cmdWidget)
        self.__logWidget = LogWidget(self)
        self.__dockable_widgets.append(self.__logWidget)
        self.__codeWidget = CodeWidget(self)
        self.__dockable_widgets.append(self.__codeWidget)
        self.setCentralWidget(self.__codeWidget)

        self.addDockWidget(
            Qt.DockWidgetArea.LeftDockWidgetArea, self.__regsWidget)
        self.addDockWidget(
            Qt.DockWidgetArea.LeftDockWidgetArea, self.__mapWidget)
        self.addDockWidget(
            Qt.DockWidgetArea.RightDockWidgetArea, self.__memWidget)
        self.addDockWidget(
            Qt.DockWidgetArea.RightDockWidgetArea, self.__cmdWidget)
        self.addDockWidget(
            Qt.DockWidgetArea.RightDockWidgetArea, self.__logWidget)

        # ... and the extra plugins too
        self.LoadExtraPlugins()

        # set up the menubar, status and main window
        self.setMainWindowProperty()
        self.setMainWindowMenuBar()

        # set up on-quit hooks
        self.__app.aboutToQuit.connect(self.onAboutToQuit)

        # show everything
        self.show()
        return

    def __del__(self):
        """
        Overriding CEmuWindow deletion procedure
        """
        return

    def onAboutToQuit(self):
        """
        Overriding the aboutToSignal handler
        """
        if self.settings.getboolean("Global", "SaveConfigOnExit"):
            self.settings.save()
            ok("Settings saved...")
        return

    def LoadExtraPlugins(self) -> int:
        nb_added = 0

        for p in list_available_plugins():
            module = load_plugin(p.stem)
            if not module or not getattr(module, "register"):
                warn(f"module {p} is invalid")
                continue

            m = module.register(self)
            if not m:
                warn(f"missing `register()` in module {p}")
                continue

            self.__plugins.append(m)
            nb_added += 1
            self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, m)
            info("Loaded plugin '{}'".format(p))
        return nb_added

    def setMainWindowProperty(self) -> None:
        width = self.settings.getint("Global", "WindowWidth", 1600)
        heigth = self.settings.getint("Global", "WindowHeigth", 800)
        self.resize(width, heigth)
        self.updateTitle()

        # center the window
        frame_geometry = self.frameGeometry()
        screen = self.screen().availableGeometry().center()
        frame_geometry.moveCenter(screen)
        self.move(frame_geometry.topLeft())

        # apply the style
        style = self.settings.get("Theme", "QtStyle", "Cleanlooks")
        self.__app.setStyle(style)
        return

    def add_menu_item(self, title: str, callback: Callable, description: str = "", shortcut: str = "", **kwargs) -> QAction:
        """
        Helper function to create a QAction for the menu bar.
        """

        action = QAction(QIcon(), title, self)
        if "checkable" in kwargs:
            action.setCheckable(kwargs["checkable"])
            if "checked" in kwargs:
                action.setChecked(kwargs["checkable"])

        action.triggered.connect(callback)
        if description:
            action.setStatusTip(description)
        if shortcut:
            action.setShortcut(shortcut)
        return action

    def setMainWindowMenuBar(self):
        statusBar = self.statusBar()
        menubar = self.menuBar()
        maxRecentFiles = self.settings.getint("Global", "MaxRecentFiles")

        # Create "File" menu option
        fileMenu = menubar.addMenu("&File")

        loadAsmAction = self.add_menu_item("Load Assembly", self.loadCodeText,
                                           self.shortcuts.description(
                                               "load_assembly"),
                                           self.shortcuts.shortcut("load_assembly"))

        loadBinAction = self.add_menu_item("Load Binary", self.loadCodeBin,
                                           self.shortcuts.description(
                                               "load_binary"),
                                           self.shortcuts.shortcut("load_binary"))

        for _ in range(maxRecentFiles):
            self.recentFileActions.append(
                QAction(self, visible=False, triggered=self.openRecentFile))

        clearRecentFilesAction = self.add_menu_item("Clear Recent Files", self.clearRecentFiles,
                                                    "Clear Recent Files", "")

        # "Save As" sub-menu
        saveAsSubMenu = QMenu("Save As", self)

        saveAsmAction = self.add_menu_item("Save Assembly", self.saveCodeText,
                                           self.shortcuts.description(
                                               "save_as_asm"),
                                           self.shortcuts.shortcut("save_as_asm"))

        saveBinAction = self.add_menu_item("Save Binary", self.saveCodeBin,
                                           self.shortcuts.description(
                                               "save_as_binary"),
                                           self.shortcuts.shortcut("save_as_binary"))

        saveAsSubMenu.addAction(saveAsmAction)
        saveAsSubMenu.addAction(saveBinAction)

        fileMenu.addMenu(saveAsSubMenu)

        # "Export As" sub-menu
        exportAsSubMenu = QMenu("Export As", self)
        saveCAction = self.add_menu_item("Generate C code", self.saveAsCFile,
                                         self.shortcuts.description(
                                             "generate_c_file"),
                                         self.shortcuts.shortcut("generate_c_file"))

        saveAsAsmAction = self.add_menu_item("Generate Assembly code", self.saveAsAsmFile,
                                             self.shortcuts.description(
                                                 "generate_asm_file"),
                                             self.shortcuts.shortcut("generate_asm_file"))

        generatePeAction = self.add_menu_item("Generate PE executable", self.generate_pe,
                                              self.shortcuts.description(
                                                  "generate_pe_exe"),
                                              self.shortcuts.shortcut("generate_pe_exe"))

        # generateElfAction = self.add_menu_item("Generate ELF executable", self.generate_elf,
        #                                     self.shortcuts.description("generate_elf_exe"),
        #                                     self.shortcuts.shortcut("generate_elf_exe"))

        exportAsSubMenu.addAction(saveCAction)
        exportAsSubMenu.addAction(saveAsAsmAction)
        exportAsSubMenu.addAction(generatePeAction)
        # exportAsSubMenu.addAction(generateElfAction)

        fileMenu.addMenu(exportAsSubMenu)
        fileMenu.addSeparator()

        # "Load" sub-menu
        loadSubMenu = QMenu("Load", self)
        loadSubMenu.addAction(loadAsmAction)
        loadSubMenu.addAction(loadBinAction)

        fileMenu.addMenu(loadSubMenu)
        fileMenu.addSeparator()

        for i in range(maxRecentFiles):
            fileMenu.addAction(self.recentFileActions[i])
        self.updateRecentFileActions()
        fileMenu.addSeparator()

        fileMenu.addAction(clearRecentFilesAction)
        fileMenu.addSeparator()

        quitAction = self.add_menu_item("Quit", QApplication.quit,
                                        self.shortcuts.shortcut(
                                            "exit_application"),
                                        self.shortcuts.description("exit_application"))

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

                self.archActions[arch.name].setStatusTip(
                    f"Switch context to architecture: '{arch}'")
                self.archActions[arch.name].triggered.connect(
                    functools.partial(self.onUpdateArchitecture, arch))
                archSubMenu.addAction(self.archActions[arch.name])

        # Add the View Window menu bar
        viewWindowsMenu = menubar.addMenu("&View")
        for w in self.__dockable_widgets:
            name = w.windowTitle()
            action = self.add_menu_item(
                name, self.onCheckWindowMenuBarItem, f"Window '{name}'", checkable=True, checked=True)
            viewWindowsMenu.addAction(action)

        # Add Help menu bar
        helpMenu = menubar.addMenu("&Help")
        shortcutAction = self.add_menu_item("Shortcuts", self.showShortcutPopup,
                                            self.shortcuts.description(
                                                "shortcut_popup"),
                                            self.shortcuts.shortcut("shortcut_popup"))

        aboutAction = self.add_menu_item("About", self.about_popup,
                                         self.shortcuts.description("about_popup"))

        helpMenu.addAction(shortcutAction)
        helpMenu.addAction(aboutAction)
        return

    def get_widget_by_name(self, name: str) -> Optional[QDockWidget]:
        """
        Helper function to find a QDockWidget from its title
        """
        for w in self.__dockable_widgets:
            if w.windowTitle() == name:
                return w
        return None

    def onCheckWindowMenuBarItem(self, state: bool) -> None:
        """
        Callback for toggling the visibility of dockable widgets
        """
        name = self.sender().text()
        widget = self.get_widget_by_name(name)
        if widget:
            widget.hide() if state == False else widget.show()
        return

    def loadFile(self, fname: str, data=None):

        if not data:
            data = open(fname, 'r').read()

        for line in data.splitlines():
            part = line.strip().split()
            if len(part) < 3:
                continue

            if (part[0], part[1]) != (COMMENT_MARKER, PROPERTY_MARKER):
                continue

            if part[2].startswith("arch:"):
                try:
                    arch_from_file = part[2][5:]
                    arch = get_architecture_by_name(arch_from_file)
                    self.onUpdateArchitecture(arch)
                except KeyError:
                    error(
                        f"Unknown architecture '{arch_from_file:s}', discarding...")
                    continue

            if part[2].startswith("endian:"):
                endian_from_file = part[2][7:].lower()
                if endian_from_file not in ("little", "big"):
                    error(
                        f"Incorrect endianness '{endian_from_file:s}', discarding...")
                    continue
                self.arch.endianness = Endianness.LITTLE_ENDIAN if endian_from_file == "little" else Endianness.BIG_
                ok(f"Changed endianness to '{endian_from_file:s}'")

            if part[2].startswith("syntax:"):
                syntax_from_file = part[2][7:].lower()
                if syntax_from_file not in ("att", "intel"):
                    error(
                        f"Incorrect syntax '{syntax_from_file:s}', discarding...")
                    continue
                self.arch.syntax = Syntax.ATT if syntax_from_file == "att" else Syntax.INTEL
                ok(f"Changed syntax to '{syntax_from_file:s}'")

        self.__codeWidget.editor.setPlainText(data)
        ok(f"Loaded '{fname}'")
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
        qFile, _ = QFileDialog.getOpenFileName(
            self, title, str(EXAMPLE_PATH), filter + ";;All files (*.*)")

        if not os.access(qFile, os.R_OK):
            error(f"Failed to read '{qFile}'")
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
        qFile, _ = QFileDialog().getSaveFileName(
            self, title, str(HOME), filter=filter + ";;All files (*.*)")
        if not qFile:
            return

        if run_assembler:
            asm = self.get_code(as_string=True)
            txt, cnt = assemble(asm, self.arch)
            if cnt < 0:
                error(f"Failed to compile: error at line {-cnt:d}")
                return
        else:
            txt = self.get_code(as_string=True)

        with open(qFile, "wb") as f:
            f.write(txt)

        ok(f"Saved as '{qFile:s}'")
        return

    def saveCodeText(self):
        return self.saveCode("Save Assembly Pane As", "Assembly files (*.asm *.s)", False)

    def saveCodeBin(self):
        return self.saveCode("Save Raw Binary Pane As", "Raw binary files (*.raw)", True)

    def saveAsCFile(self):
        template = (TEMPLATE_PATH / "template.c").open("rb").read()
        insns = self.__codeWidget.parser.getCleanCodeAsByte(as_string=False)
        title = bytes(self.arch.name, encoding="utf-8")
        sc = b'""\n'
        i = 0
        for insn in insns:
            txt, cnt = assemble(insn, self.arch)
            if cnt < 0:
                info("Failed to compile: error at line {:d}".format(-cnt))
                return

            c = b'"' + b''.join([b'\\x%.2x' % txt[i]
                                for i in range(len(txt))]) + b'"'
            c = c.ljust(60, b' ')
            c += b'// ' + insn + b'\n'
            sc += b'\t' + c
            i += len(txt)

        sc += b'\t""'
        body = template % (title, i, sc)
        fd, fpath = tempfile.mkstemp(suffix=".c")
        os.write(fd, body)
        os.close(fd)
        info("Saved as '%s'" % fpath)
        return

    def generate_pe(self) -> None:
        """
        Uses LIEF to create a valid PE from the current session
        """
        memory_layout = self.get_memory_layout()
        asm_code, nb_insns = assemble(self.get_code(as_string=True), self.arch)
        if nb_insns:
            try:
                outfile = build_pe_executable(
                    asm_code, memory_layout, self.arch)
                info("PE file written as '{}'".format(outfile))
            except Exception as e:
                info("PE creation triggered an exception: {}".format(str(e)))
        return

    def generate_elf(self) -> None:
        """
        Uses LIEF to create a valid ELF from the current session
        """
        memory_layout = self.get_memory_layout()
        asm_code, nb_insns = assemble(self.get_code(as_string=True), self.arch)
        if nb_insns:
            try:
                outfile = build_elf_executable(
                    asm_code, memory_layout, self.arch)
                info(f"ELF file written as '{outfile}'")
            except Exception as e:
                info(f"ELF creation triggered an exception: {e}")
        return

    def saveAsAsmFile(self) -> None:
        asm_fmt = (TEMPLATE_PATH / "template.asm").open("rb").read()
        txt = self.__codeWidget.parser.getCleanCodeAsByte(as_string=True)
        title = bytes(self.arch.name, encoding="utf-8")
        asm = asm_fmt % (title, b'\n'.join(
            [b"\t%s" % x for x in txt.split(b'\n')]))
        with tempfile.NamedTemporaryFile("wb", suffix=".asm", delete=False) as fd:
            fd.write(asm)
            info(f"Saved as '{fd.name}'")
        return

    def onUpdateArchitecture(self, arch: Architecture) -> None:
        self.currentAction.setEnabled(True)
        self.arch = arch
        info(f"Switching to '{self.arch}'")
        self.__regsWidget.updateGrid()
        self.archActions[arch.name].setEnabled(False)
        self.currentAction = self.archActions[arch.name]
        self.updateTitle()
        return

    def updateTitle(self, msg: str = "") -> None:
        title = f"{TITLE} ({self.arch})"
        if msg:
            title += f": {msg}"
        self.setWindowTitle(title)
        return

    def showShortcutPopup(self):
        msgbox = QMessageBox(self)
        msgbox.setWindowTitle(
            "CEMU Shortcuts from: {:s}".format(CONFIG_FILEPATH))

        wid = QWidget()
        grid = QGridLayout()
        for j, title in enumerate(["Shortcut", "Description"]):
            lbl = QLabel()
            lbl.setTextFormat(Qt.TextFormat.RichText)
            lbl.setText(f"<b>{title}</b>")
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

    def about_popup(self):
        templ = (TEMPLATE_PATH / "about.html").open().read()
        desc = templ.format(author=AUTHOR, version=VERSION,
                            project_link=URL, issues_link=ISSUE_LINK)
        msgbox = QMessageBox(self)
        msgbox.setIcon(QMessageBox.Icon.Information)
        msgbox.setWindowTitle("About CEMU")
        msgbox.setTextFormat(Qt.TextFormat.RichText)
        msgbox.setText(desc)
        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgbox.exec()
        return

    def updateRecentFileActions(self, insert_file=None):
        settings = QSettings('Cemu', 'Recent Files')
        files = settings.value('recentFileList')
        if files is None:
            # if setting doesn't exist, create it
            settings.setValue('recentFileList', [])
            files = settings.value('recentFileList')

        maxRecentFiles = self.settings.getint("Default", "MaxRecentFiles")

        if insert_file:
            if insert_file not in files:
                files.insert(0, insert_file)
            if len(files) > maxRecentFiles:
                files = files[0:maxRecentFiles]

            settings.setValue('recentFileList', files)

        numRecentFiles = min(len(files), maxRecentFiles)

        for i in range(numRecentFiles):
            _file = files[i]
            _filename = QFileInfo(_file).fileName()
            text = f"&{i+1:d} {_filename:s}"
            self.recentFileActions[i].setText(text)
            self.recentFileActions[i].setData(_file)
            self.recentFileActions[i].setVisible(True)

        for j in range(numRecentFiles, maxRecentFiles):
            self.recentFileActions[j].setVisible(False)
        return

    def clearRecentFiles(self) -> None:
        settings = QSettings('Cemu', 'Recent Files')
        settings.setValue('recentFileList', [])
        self.updateRecentFileActions()
        return

    def get_code(self, as_string: bool = False) -> bytearray:
        """
        Return as a bytearray the code from the code editor.
        """
        return self.__codeWidget.parser.getCleanCodeAsByte(as_string)

    def get_registers(self) -> dict[str, int]:
        """
        Returns the register widget values as a Dict
        """
        self.__regsWidget.updateGrid()
        return self.__regsWidget.getRegisterValues()

    def get_memory_layout(self) -> list[MemorySection]:
        """
        Returns the memory layout as defined by the __mapWidget values as a structured list.
        """
        return self.__mapWidget.maps
