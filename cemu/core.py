import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

import cemu.const
import cemu.log
import cemu.ui.main
import cemu.plugins
import cemu.settings
import cemu.emulator
import cemu.arch


class BackendContext:
    settings: cemu.settings.Settings
    __emulator: cemu.emulator.Emulator
    __architecture: cemu.arch.Architecture
    # plugins: list[cemu.plugins.CemuPlugin] = []

    def __init__(self):
        cemu.arch.load_architectures()

        self.settings = cemu.settings.Settings()
        default_arch = self.settings.get(
            "Global", "DefaultArchitecture", "x86_64")
        self.__architecture = cemu.arch.get_architecture_by_name(default_arch)
        self.__emulator = cemu.emulator.Emulator()
        return

    @property
    def architecture(self) -> cemu.arch.Architecture:
        return self.__architecture

    @architecture.setter
    def architecture(self, new_arch: cemu.arch.Architecture):
        cemu.log.dbg(
            f"Changing architecture {self.architecture} to {new_arch}")
        self.__architecture = new_arch
        cemu.log.dbg(f"Refreshing emulator for {self.architecture}")
        self.__emulator.create_new_vm()
        return

    @property
    def emulator(self) -> cemu.emulator.Emulator:
        return self.__emulator


context = BackendContext()


def Cemu(args: list[str]):
    """Entry point of the GUI

    Args:
        args (list[str]): _description_
    """
    if cemu.const.DEBUG:
        cemu.log.register_sink(print)
        cemu.log.dbg("Starting in Debug Mode")

    app = QApplication(args)
    app.setStyleSheet(cemu.const.DEFAULT_STYLE_PATH.open().read())
    app.setWindowIcon(QIcon(str(cemu.const.ICON_PATH.absolute())))
    cemu.ui.main.CEmuWindow(app)
    sys.exit(app.exec())
