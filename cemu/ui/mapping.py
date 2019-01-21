import os
from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import (
    QVBoxLayout,
    QTableWidget,
    QHeaderView,
    QTableWidgetItem,
    QWidget
)


from cemu.utils import (
    ishex
)


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