import os
from PyQt5.QtCore import (
    Qt,
    QVariant,
    QStringListModel
)

from PyQt5.QtWidgets import (
    QVBoxLayout,
    QTableWidget,
    QHeaderView,
    QTableWidgetItem,
    QDockWidget,
    QWidget,
    QTableView,
    QListView,
)

from cemu.memory import (
    MemorySection,
    MemoryLayoutEntryType,
)

from cemu.utils import (
    ishex,
)


from typing import List, Tuple, Any


class MemoryMappingWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(MemoryMappingWidget, self).__init__("Memory map", parent)
        self.log = self.parentWidget().log
        layout = QVBoxLayout()
        self.memory_mapping = [
            MemorySection(".text",  0x00040000, 0x1000, "READ|EXEC",  None),
            MemorySection(".data",  0x00060000, 0x1000, "READ|WRITE", None),
            MemorySection(".stack", 0x00080000, 0x4000, "READ|WRITE", None),
            MemorySection(".misc",  0x00070000, 0x1000, "ALL",        None),
        ]
        model = QStringListModel([ str(x) for x in self.memory_mapping ])
        view = QListView()
        view.setModel(model)
        layout.addWidget(view)
        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)
        return


    @property
    def maps(self) -> List[MemoryLayoutEntryType]:
        self.__maps = [ entry.export() for entry in self.memory_mapping ]
        return self.__maps