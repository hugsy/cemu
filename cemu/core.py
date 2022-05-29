from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

import cemu.arch
import cemu.const
import cemu.emulator
import cemu.log
import cemu.plugins
import cemu.settings
import cemu.ui.main


class BackendContext:
    settings: cemu.settings.Settings
    __emulator: cemu.emulator.Emulator
    __architecture: cemu.arch.Architecture
    __root: cemu.ui.main.CEmuWindow

    def __init__(self):
        self.settings = cemu.settings.Settings()
        self.__emulator = cemu.emulator.Emulator()
        default_arch = self.settings.get(
            "Global", "DefaultArchitecture", "x86_64")
        self.__architecture = cemu.arch.Architectures.find(default_arch)
        return

    @property
    def architecture(self) -> cemu.arch.Architecture:
        return self.__architecture

    @architecture.setter
    def architecture(self, new_arch: cemu.arch.Architecture):
        cemu.log.dbg(
            f"Changing architecture {self.__architecture} to {new_arch}")
        self.__architecture = new_arch
        cemu.log.dbg(f"Resetting emulator for {self.__architecture}")
        self.__emulator.reset()
        return

    @property
    def emulator(self) -> cemu.emulator.Emulator:
        return self.__emulator

    @property
    def root(self) -> cemu.ui.main.CEmuWindow:
        return self.__root

    @root.setter
    def root(self, root: cemu.ui.main.CEmuWindow):
        self.__root = root


context = BackendContext()


def Cemu(args: list[str]):
    """Entry point of the GUI

    Args:
        args (list[str]): _description_
    """
    global context

    if cemu.const.DEBUG:
        cemu.log.register_sink(print)
        cemu.log.dbg("Starting in Debug Mode")

    app = QApplication(args)
    app.setStyleSheet(cemu.const.DEFAULT_STYLE_PATH.open().read())
    app.setWindowIcon(QIcon(str(cemu.const.ICON_PATH.absolute())))
    context.root = cemu.ui.main.CEmuWindow(app)
    sys.exit(app.exec())
