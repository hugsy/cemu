import functools
import os
import pathlib
import tempfile
from typing import Callable, Optional

import unicorn
from PyQt6.QtCore import QFileInfo, QSettings, Qt
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QGridLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QWidget,
)

import cemu.core
import cemu.exports
import cemu.plugins
import cemu.utils
from cemu.emulator import EmulatorState
from cemu.log import dbg, error, info, ok, warn
from cemu.ui.utils import popup

from ..arch import Architecture, Architectures, Endianness
from ..const import (
    AUTHOR,
    CONFIG_FILEPATH,
    EXAMPLE_PATH,
    HOME,
    ISSUE_LINK,
    TEMPLATE_PATH,
    TITLE,
    URL,
    VERSION,
)
from ..memory import MemorySection
from ..shortcuts import ShortcutManager
from .codeeditor import CodeWidget
from .command import CommandWidget
from .log import LogWidget
from .mapping import MemoryMappingWidget
from .memory import MemoryWidget
from .registers import RegistersWidget


class CEmuWindow(QMainWindow):
    def __init__(self, app: QApplication, *args, **kwargs):
        super(CEmuWindow, self).__init__()
        assert cemu.core.context is not None
        assert isinstance(cemu.core.context, cemu.core.GlobalGuiContext)

        self.rootWindow = self
        self.__app = app
        self.recentFileActions: list[QAction] = []
        self.__dockable_widgets: list[QDockWidget] = []
        self.archActions = {}
        self.signals = {}
        self.current_file: Optional[pathlib.Path] = None
        self.__background_emulator_thread = EmulationRunner()
        cemu.core.context.emulator.set_threaded_runner(
            self.__background_emulator_thread
        )

        self.shortcuts = ShortcutManager()

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

        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.__regsWidget)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.__mapWidget)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.__memWidget)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.__cmdWidget)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.__logWidget)

        # ... and the extra plugins too
        self.LoadExtraPlugins()

        # set up the menubar, status and main window
        self.setMainWindowProperty()
        self.setMainWindowMenuBar()

        # set up on-quit hooks
        self.__app.aboutToQuit.connect(self.onAboutToQuit)

        # register the callbacks for the emulator
        emu = cemu.core.context.emulator
        emu.add_state_change_cb(
            EmulatorState.NOT_RUNNING, self.update_layout_not_running
        )
        emu.add_state_change_cb(EmulatorState.RUNNING, self.update_layout_running)
        emu.add_state_change_cb(EmulatorState.IDLE, self.update_layout_step_running)
        emu.add_state_change_cb(
            EmulatorState.FINISHED, self.update_layout_step_finished
        )

        # show everything
        self.show()
        dbg("Main window initialized")

        #
        # set the emulator to a new context
        #
        emu.reset()
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
        if cemu.core.context.settings.getboolean("Global", "SaveConfigOnExit"):
            cemu.core.context.settings.save()
            ok("Settings saved...")
        return

    def LoadExtraPlugins(self) -> int:
        nb_added = 0

        for path in cemu.plugins.list():
            module = cemu.plugins.load(path)
            if not module:
                continue

            m = module.register(self)
            if not m:
                error(f"The registration of '{path}' failed")
                continue

            self.__dockable_widgets.append(m)
            self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, m)
            ok(f"Loaded plugin '{path}'")
            nb_added += 1
        return nb_added

    def setMainWindowProperty(self) -> None:
        width = cemu.core.context.settings.getint("Global", "WindowWidth", 1600)
        heigth = cemu.core.context.settings.getint("Global", "WindowHeigth", 800)
        self.resize(width, heigth)
        self.refreshWindowTitle()

        # center the window
        frame_geometry = self.frameGeometry()
        screen = self.screen().availableGeometry().center()
        frame_geometry.moveCenter(screen)
        self.move(frame_geometry.topLeft())

        # apply the style
        style = cemu.core.context.settings.get("Theme", "QtStyle", "Cleanlooks")
        self.__app.setStyle(style)
        return

    def addMenuItem(
        self,
        title: str,
        callback: Callable,
        description: str = "",
        shortcut: str = "",
        **kwargs,
    ) -> QAction:
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
        self.statusBar()
        menubar = self.menuBar()
        maxRecentFiles = cemu.core.context.settings.getint("Global", "MaxRecentFiles")

        # Create "File" menu options
        fileMenu = menubar.addMenu("&File")

        # "Open File" submenu
        openAsmAction = self.addMenuItem(
            "Open Assembly Text",
            self.loadCodeText,
            self.shortcuts.description("load_assembly"),
            self.shortcuts.shortcut("load_assembly"),
        )

        openBinAction = self.addMenuItem(
            "Open Raw Binary",
            self.loadCodeBin,
            self.shortcuts.description("load_binary"),
            self.shortcuts.shortcut("load_binary"),
        )

        openDumpAction = self.addMenuItem("Open Dump File", self.loadDumpFile)

        openSubMenu = QMenu("Open File", self)
        openSubMenu.addAction(openAsmAction)
        openSubMenu.addAction(openBinAction)
        openSubMenu.addAction(openDumpAction)

        fileMenu.addMenu(openSubMenu)

        # "Save As" sub-menu
        saveAsSubMenu = QMenu("Save File", self)

        saveAsmAction = self.addMenuItem(
            "As Assembly",
            self.saveCodeText,
            self.shortcuts.description("save_as_asm"),
            self.shortcuts.shortcut("save_as_asm"),
        )

        saveBinAction = self.addMenuItem(
            "As Binary",
            self.saveCodeBin,
            self.shortcuts.description("save_as_binary"),
            self.shortcuts.shortcut("save_as_binary"),
        )

        saveAsSubMenu.addAction(saveAsmAction)
        saveAsSubMenu.addAction(saveBinAction)

        fileMenu.addMenu(saveAsSubMenu)

        # "Export" sub-menu
        exportAsSubMenu = QMenu("Export", self)
        saveCAction = self.addMenuItem(
            "Generate C code",
            self.saveAsCFile,
            self.shortcuts.description("generate_c_file"),
            self.shortcuts.shortcut("generate_c_file"),
        )

        saveAsAsmAction = self.addMenuItem(
            "Generate Assembly code",
            self.saveAsAsmFile,
            self.shortcuts.description("generate_asm_file"),
            self.shortcuts.shortcut("generate_asm_file"),
        )

        generatePeAction = self.addMenuItem(
            "Generate PE executable",
            self.generate_pe,
            self.shortcuts.description("generate_pe_exe"),
            self.shortcuts.shortcut("generate_pe_exe"),
        )

        generateElfAction = self.addMenuItem(
            "Generate ELF executable",
            self.generate_elf,
            self.shortcuts.description("generate_elf_exe"),
            self.shortcuts.shortcut("generate_elf_exe"),
        )

        exportAsSubMenu.addAction(saveCAction)
        exportAsSubMenu.addAction(saveAsAsmAction)
        exportAsSubMenu.addAction(generatePeAction)
        exportAsSubMenu.addAction(generateElfAction)

        fileMenu.addMenu(exportAsSubMenu)

        fileMenu.addSeparator()

        # "Open recent files" submenu
        openRecentFilesSubMenu = QMenu("Open Recent Files", self)
        for _ in range(maxRecentFiles):
            action = QAction(self)
            action.setVisible(False)
            action.triggered.connect(self.openRecentFile)
            self.recentFileActions.append(action)

        clearRecentFilesAction = self.addMenuItem(
            "Clear Recent Files", self.clearRecentFiles, "Clear Recent Files", ""
        )

        openRecentFilesSubMenu.addActions(self.recentFileActions)
        openRecentFilesSubMenu.addSeparator()
        openRecentFilesSubMenu.addAction(clearRecentFilesAction)
        fileMenu.addMenu(openRecentFilesSubMenu)

        self.updateRecentFileActions()

        # "Quit" action

        fileMenu.addSeparator()

        quitAction = self.addMenuItem(
            "Quit",
            QApplication.quit,
            self.shortcuts.shortcut("exit_application"),
            self.shortcuts.description("exit_application"),
        )

        fileMenu.addAction(quitAction)

        # Add Architecture menu bar
        archMenu = menubar.addMenu("&Architecture")
        for abi in sorted(Architectures.keys()):
            archSubMenu = archMenu.addMenu(abi)
            for arch in Architectures[abi]:
                self.archActions[arch.name] = QAction(QIcon(), str(arch), self)
                if arch == cemu.core.context.architecture:
                    self.archActions[arch.name].setEnabled(False)
                    self.currentAction = self.archActions[arch.name]

                self.archActions[arch.name].setStatusTip(
                    f"Change the architecture to '{arch.name}'"
                )
                self.archActions[arch.name].triggered.connect(
                    functools.partial(self.onUpdateArchitecture, arch)
                )
                archSubMenu.addAction(self.archActions[arch.name])

        # Add the View Window menu bar
        viewWindowsMenu = menubar.addMenu("&View")
        toggleFocusMode = self.addMenuItem(
            "Toggle Focus Mode",
            self.toggleFocusMode,
            self.shortcuts.description("toggle_focus_mode"),
            self.shortcuts.shortcut("toggle_focus_mode"),
            checkable=True,
            checked=True,
        )
        viewWindowsMenu.addAction(toggleFocusMode)

        viewWindowsMenu.addSeparator()

        for w in self.__dockable_widgets:
            name = w.windowTitle()
            action = self.addMenuItem(
                name,
                self.onCheckWindowMenuBarItem,
                f"Window '{name}'",
                checkable=True,
                checked=True,
            )
            viewWindowsMenu.addAction(action)

        # Add Help menu bar
        helpMenu = menubar.addMenu("&Help")
        shortcutAction = self.addMenuItem(
            "Shortcuts",
            self.showShortcutPopup,
            self.shortcuts.description("shortcut_popup"),
            self.shortcuts.shortcut("shortcut_popup"),
        )

        aboutAction = self.addMenuItem(
            "About", self.about_popup, self.shortcuts.description("about_popup")
        )

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

    def onCheckWindowMenuBarItem(self, _: bool) -> None:
        """
        Callback for toggling the visibility of dockable widgets
        """
        name: str = self.sender().text()  # type: ignore
        widget = self.get_widget_by_name(name)
        if not widget:
            return
        if widget.isVisible():
            widget.hide()
        else:
            widget.show()
        return

    def toggleFocusMode(self, checked: bool) -> None:
        """
        Toggle the Focus Mode - if enabled, hide all panes except the CodeView
        """
        if checked:
            dbg("Switching to 'Focus Mode'")
        else:
            dbg("Switching back from 'Focus Mode'")

        for w in self.__dockable_widgets:
            if w.windowTitle() == "Code View":
                w.show()
                continue

            if checked:
                w.hide()
            else:
                w.show()
        return

    def loadFile(self, fpath: pathlib.Path) -> None:
        """_summary_ Load a file from disk

        Args:
            content (Union[pathlib.Path, str]): _description_

        Raises:
            TypeError: if `content` has an invalid type
            KeyError: if the architecture from the file metadata is invalid
        """
        dbg(f"Trying to load '{fpath}'")
        content = fpath.open().read()

        try:
            res = cemu.utils.get_metadata_from_stream(content)
        except KeyError as ke:
            error(f"Exception while parsing metadata: {str(ke)}")
            return

        if res:
            # metadata found
            arch, endian = res
            self.onUpdateArchitecture(arch, endian)
        else:
            # no metadata, use current context
            pass

        # popuplate the code pane
        self.__codeWidget.editor.setPlainText(content)
        ok(f"Succesfully loaded '{fpath}'")
        self.updateRecentFileActions(fpath)
        self.current_file = fpath
        self.refreshWindowTitle()
        return

    def openRecentFile(self):
        action = self.sender()
        if action:
            self.loadFile(action.data())  # type: ignore
        return

    def loadCode(self, title, filter, run_disassembler):
        qFile, _ = QFileDialog.getOpenFileName(
            self, title, str(EXAMPLE_PATH), filter + ";;All files (*.*)"
        )

        fpath = pathlib.Path(qFile).resolve().absolute()
        if not fpath.is_file():
            error(f"Failed to read '{fpath}'")
            return

        if run_disassembler:
            with tempfile.NamedTemporaryFile("w", suffix=".asm", delete=False) as fd:
                disassembled_instructions = cemu.utils.disassemble_file(fpath)
                fd.write(
                    os.linesep.join(
                        [
                            f"{insn.mnemonic}, {insn.operands}"
                            for insn in disassembled_instructions
                        ]
                    )
                )
                fpath = pathlib.Path(fd.name)

        self.loadFile(fpath)
        return

    def loadCodeText(self):
        return self.loadCode("Open Assembly file", "Assembly files (*.asm *.s)", False)

    def loadCodeBin(self):
        return self.loadCode("Open Raw file", "Raw binary files (*.raw)", True)

    def loadDumpFile(self):
        error("Not implemented yet")
        # parse dump
        # populate memory
        # populate registers
        # self.loadCode("Open Dump file", "Core Dump files (*.core *.dump *.dmp)", True)

    def saveCode(self, title, filter, run_assembler):
        dbg(f"Saving content of '{title}'")
        qFile, _ = QFileDialog().getSaveFileName(
            self, title, str(HOME), filter=filter + ";;All files (*.*)"
        )

        if not qFile:
            return

        fpath = pathlib.Path(qFile)
        if fpath.exists():
            warn(f"'{fpath}' already exists and will be overwritten")

        if run_assembler:
            raw_assembly = self.get_codeview_content()
            insns: list[cemu.utils.Instruction] = cemu.utils.assemble(raw_assembly)
            raw_bytecode = b"".join([insn.bytes for insn in insns])
            fpath.open("wb").write(raw_bytecode)
        else:
            raw_bytecode = self.get_codeview_content()
            fpath.open("w").write(raw_bytecode)

        ok(f"Saved as '{fpath}'")
        return

    def saveCodeText(self):
        return self.saveCode(
            "Save Assembly Pane As", "Assembly files (*.asm *.s)", False
        )

    def saveCodeBin(self):
        return self.saveCode(
            "Save Raw Binary Pane As", "Raw binary files (*.raw)", True
        )

    def saveAsCFile(self):
        template = (TEMPLATE_PATH / "template.c").open("r").read()
        output: list[str] = []
        lines = self.get_codeview_content().splitlines()
        insns = cemu.utils.assemble(self.get_codeview_content())
        for i, insn in enumerate(insns):
            hexa = ", ".join([f"{b:#02x}" for b in insn.bytes])
            line = f"/* {i:#08x} */   {hexa}   // {lines[i]}"
            output.append(line)

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".c") as fd:
            body = template % (
                cemu.core.context.architecture.name,
                len(insns),
                os.linesep.join(output),
            )
            fd.write(body)
            ok(f"Saved as '{fd.name}'")
        return

    def generate_pe(self) -> None:
        """Uses LIEF to create a valid PE from the current session"""
        memory_layout = self.get_memory_layout()
        code = self.get_codeview_content()
        try:
            insns = cemu.utils.assemble(code)
            if len(insns) > 0:
                asm_code = b"".join([x.bytes for x in insns])
                pe = cemu.exports.build_pe_executable(
                    asm_code, memory_layout, cemu.core.context.architecture
                )
                info(f"PE file written as '{pe}'")
        except Exception as e:
            error(f"PE creation triggered an exception: {e}")
        return

    def generate_elf(self) -> None:
        """Uses LIEF to create a valid ELF from the current session"""
        memory_layout = self.get_memory_layout()
        code = self.get_codeview_content()
        try:
            insns = cemu.utils.assemble(code)
            if len(insns) > 0:
                asm_code = b"".join([x.bytes for x in insns])
                elf = cemu.exports.build_pe_executable(
                    asm_code, memory_layout, cemu.core.context.architecture
                )
                info(f"ELF file written as '{elf}'")
        except Exception as e:
            error(f"ELF creation triggered an exception: {str(e)}")
        return

    def saveAsAsmFile(self) -> None:
        """Write the content of the ASM pane to disk"""
        template = (TEMPLATE_PATH / "template.asm").open("r").read()
        code = self.get_codeview_content()

        with tempfile.NamedTemporaryFile("w", suffix=".asm", delete=False) as fd:
            body = template % (cemu.core.context.architecture.name, code)
            fd.write(body)
            ok(f"Saved as '{fd.name}'")
        return

    def onUpdateArchitecture(
        self, arch: Architecture, endian: Optional[Endianness] = None
    ) -> None:
        """Callback triggered when there's a change of Architecture in the UI

        Args:
            arch (Architecture): the newly selected architecture
        """
        self.currentAction.setEnabled(True)
        cemu.core.context.architecture = arch
        if endian:
            cemu.core.context.architecture.endianness = endian
        info(f"Switching to '{cemu.core.context.architecture}'")
        self.__regsWidget.updateGrid()
        self.archActions[arch.name].setEnabled(False)
        self.currentAction = self.archActions[arch.name]
        self.refreshWindowTitle()
        return

    def refreshWindowTitle(self) -> None:
        """Refresh the main window title bar"""
        title = f"{TITLE} ({cemu.core.context.architecture})"
        if self.current_file:
            title += f": {self.current_file.name}"
        self.setWindowTitle(title)
        return

    def showShortcutPopup(self):
        """Display a popup with all shortcuts currently defined"""
        msgbox = QMessageBox(self)
        msgbox.setWindowTitle("CEMU Shortcuts from: {:s}".format(CONFIG_FILEPATH))

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
            grid.addWidget(QLabel(sc), i + 1, 0)
            grid.addWidget(QLabel(desc), i + 1, 1)

        wid.setMinimumWidth(800)
        wid.setLayout(grid)
        msgbox.layout().addWidget(wid)
        msgbox.exec()
        return

    def about_popup(self):
        templ = (TEMPLATE_PATH / "about.html").open().read()
        desc = templ.format(
            author=AUTHOR, version=VERSION, project_link=URL, issues_link=ISSUE_LINK
        )
        msgbox = QMessageBox(self)
        msgbox.setIcon(QMessageBox.Icon.Information)
        msgbox.setWindowTitle("About CEMU")
        msgbox.setTextFormat(Qt.TextFormat.RichText)
        msgbox.setText(desc)
        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgbox.exec()
        return

    def updateRecentFileActions(self, insert_file=None):
        settings = QSettings("Cemu", "Recent Files")
        files = settings.value("recentFileList")
        if files is None:
            # if setting doesn't exist, create it
            settings.setValue("recentFileList", [])
            files = settings.value("recentFileList")

        maxRecentFiles = cemu.core.context.settings.getint("Default", "MaxRecentFiles")

        if insert_file:
            if insert_file not in files:
                files.insert(0, insert_file)
            if len(files) > maxRecentFiles:
                files = files[0:maxRecentFiles]

            settings.setValue("recentFileList", files)

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
        settings = QSettings("Cemu", "Recent Files")
        settings.setValue("recentFileList", [])
        self.updateRecentFileActions()
        return

    def get_codeview_content(self) -> str:
        """
        Return as a bytearray the code from the code editor.
        """
        return self.__codeWidget.getCleanContent()

    def get_registers(self) -> dict[str, int]:
        """
        Returns the register widget values as a Dict
        """
        self.__regsWidget.updateGrid()
        return self.__regsWidget.getRegisterValuesFromGrid()

    def get_memory_layout(self) -> list[MemorySection]:
        """
        Returns the memory layout as defined by the __mapWidget values as a structured list.
        """
        return cemu.core.context.emulator.sections

    def update_layout_not_running(self):
        self.statusBar().showMessage("Not running")
        return

    def update_layout_running(self):
        self.statusBar().showMessage("Running")
        return

    def update_layout_step_running(self):
        self.statusBar().showMessage("Idle (Step Mode)")
        return

    def update_layout_step_finished(self):
        self.statusBar().showMessage("Finished")
        return


class EmulationRunner:
    """Rusn an emulation session"""

    def run(self):
        """
        Runs the emulation
        """
        emu = cemu.core.context.emulator
        if not emu.vm:
            error("VM is not ready")
            return

        if not emu.is_running:
            error("Emulator is in invalid state")
            return

        try:
            start_address = emu.pc() or emu.start_addr
            start_offset = start_address - emu.start_addr

            #
            # Determine where to stop
            #
            if emu.use_step_mode:
                insn = emu.next_instruction(emu.code[start_offset:], start_address)
                end_address = insn.end
                info(f"Stepping from {start_address:#x} to {end_address:#x}")
            else:
                end_address = emu.start_addr + len(emu.code)
                info(f"Running all from {start_address:#x} to {end_address:#x}")

            with emu.lock:
                #
                # Run the emulator, let's go!
                #
                emu.vm.emu_start(start_address, end_address)

            #
            # If the execution is over, mark the state as finished
            #
            if emu.pc() == (emu.start_addr + len(emu.code)):
                emu.set(EmulatorState.FINISHED)
            else:
                emu.set(EmulatorState.IDLE)

        except unicorn.unicorn.UcError as e:
            popup(f"An error occured: {str(e)} at pc={emu.pc():#x}, sp={emu.sp():#x}")
            emu.set(EmulatorState.FINISHED)

        return
