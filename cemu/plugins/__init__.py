from __future__ import annotations

import importlib
import pathlib
from types import ModuleType
from typing import Generator, Optional, TYPE_CHECKING

from PyQt6.QtWidgets import QDockWidget

import cemu.core

if TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow
from cemu.const import PLUGINS_PATH
from cemu.log import error


class CemuPlugin(QDockWidget):
    def __init__(self, name: str, parent: QDockWidget):
        super().__init__(name, parent)
        self.name = name
        return

    def __str__(self):
        return self.name

    @property
    def rootWindow(self) -> CEmuWindow:
        assert isinstance(cemu.core.context, cemu.core.GlobalGuiContext)
        return cemu.core.context.root


def list() -> Generator[pathlib.Path, None, None]:
    """Browse the plugins directory to enumerate valid plugins for cemu

    Yields:
        Generator[pathlib.Path]: a iterator of `Path` for each valid plugin
    """
    for p in PLUGINS_PATH.glob("*"):
        if p.name.startswith("__"):
            continue
        yield p


def load(plugin: pathlib.Path) -> Optional[ModuleType]:
    """Load a specific cemu plugin

    Args:
        plugin (pathlib.Path): the path of the plugin to load

    Returns:
        Optional[ModuleType]: the loaded plugin module on success, None if there's no plugin, or it is invalid
    """
    try:
        if plugin.is_file():
            mod = importlib.import_module(f"cemu.plugins.{plugin.stem}")
        elif plugin.is_dir():
            mod = importlib.import_module(f"cemu.plugins.{plugin.name}")
        else:
            raise ImportError("invalid format")
    except ImportError as ie:
        error(f"Failed to import '{plugin}' - reason: {str(ie)}")
        return None

    if not hasattr(mod, "register"):
        error(f"Plugin '{plugin.stem}' has no `register` method")
        return None

    return mod
