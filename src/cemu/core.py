from __future__ import annotations

import argparse

import sys
from typing import TYPE_CHECKING, Optional, Union

import cemu.ui.main

if TYPE_CHECKING:
    from cemu.emulator import Emulator

import cemu.arch
import cemu.cli.repl
import cemu.const
import cemu.emulator
import cemu.log
import cemu.os
import cemu.settings


class GlobalContext:
    settings: cemu.settings.Settings
    __emulator: cemu.emulator.Emulator
    __architecture: cemu.arch.Architecture
    __os: cemu.os.OperatingSystem

    def __init__(self):
        self.settings = cemu.settings.Settings()
        self.__emulator = cemu.emulator.Emulator()
        default_arch = self.settings.get("Global", "DefaultArchitecture", "x86_64")
        self.__architecture = cemu.arch.Architectures.find(default_arch)
        self.__os = cemu.os.Linux
        return

    @property
    def architecture(self) -> cemu.arch.Architecture:
        return self.__architecture

    @architecture.setter
    def architecture(self, new_arch: cemu.arch.Architecture):
        cemu.log.dbg(f"Changing architecture {self.__architecture} to {new_arch}")
        self.__architecture = new_arch
        cemu.log.dbg(f"Resetting emulator for {self.__architecture}")
        self.__emulator.reset()
        return

    @property
    def emulator(self) -> "Emulator":
        return self.__emulator

    @property
    def os(self) -> cemu.os.OperatingSystem:
        return self.__os

    @os.setter
    def os(self, new_os: cemu.os.OperatingSystem):
        cemu.log.dbg(f"Changing OS {self.__os} to {new_os}")
        self.__os = new_os
        self.__emulator.reset()
        return


class GlobalGuiContext(GlobalContext):
    __root: cemu.ui.main.CEmuWindow

    @property
    def root(self) -> cemu.ui.main.CEmuWindow:
        return self.__root

    @root.setter
    def root(self, root: cemu.ui.main.CEmuWindow):
        self.__root = root


#
# The global application context. This **must** defined for cemu to operate
#
context: Optional[Union[GlobalContext, GlobalGuiContext]] = None


def CemuGui() -> None:
    """Entry point of the GUI

    Args:
        args (list[str]): _description_
    """
    global context

    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication

    cemu.log.dbg("Creating GUI context")
    context = GlobalGuiContext()

    default_style_sheet = cemu.const.DEFAULT_STYLE_PATH.read_text()

    app = QApplication(sys.argv)
    app.setStyleSheet(default_style_sheet)
    app.setWindowIcon(QIcon(str(cemu.const.ICON_PATH.absolute())))
    context.root = cemu.ui.main.CEmuWindow(app)
    sys.exit(app.exec())


def CemuCli(argv: Optional[argparse.Namespace]) -> None:
    """Entry point of the CLI

    Args:
        args (list[str]): _description_
    """
    global context

    #
    # Initialize the context
    #
    cemu.log.dbg("Creating CLI context")
    context = GlobalContext()

    #
    # Run the REPL with the command line arguments
    #
    if argv is None:
        args = argparse.ArgumentParser(prog=cemu.const.PROGNAME, description=cemu.const.DESCRIPTION)
        args.parse_args(sys.argv)
    else:
        assert isinstance(argv, argparse.Namespace)
        args = argv

    instance = cemu.cli.repl.CEmuRepl(args)
    instance.run_forever()
