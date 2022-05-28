import os
from PyQt6.QtCore import (
    Qt,
    QVariant,
    QStringListModel
)

from PyQt6.QtWidgets import (
    QVBoxLayout,
    QTableWidget,
    QHeaderView,
    QTableWidgetItem,
    QDockWidget,
    QWidget,
    QTableView,
    QListView,
    QPushButton,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QCheckBox,
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
        layout = QVBoxLayout()
        self.__memory_mapping = [
            MemorySection(".text",  0x00004000, 0x1000, "READ|EXEC"),
            MemorySection(".data",  0x00005000, 0x1000, "READ|WRITE"),
            MemorySection(".stack", 0x00006000, 0x4000, "READ|WRITE"),
            MemorySection(".misc",  0x0000a000, 0x1000, "ALL"),
        ]
        self.model = QStringListModel()
        self.model.setStringList(self.memory_mapping_str)
        self.view = QListView()
        self.view.setModel(self.model)
        layout.addWidget(self.view)
        buttons = QHBoxLayout()
        btn_add = QPushButton("Add Section")
        buttons.addWidget(btn_add)
        btn_add.clicked.connect(self.onAddSectionButtonClicked)
        buttons.addStretch(1)
        btn_del = QPushButton("Remove Section")
        btn_del.clicked.connect(self.onDeleteSectionButtonClicked)
        buttons.addWidget(btn_del)
        layout.addLayout(buttons)
        w = QWidget(self)
        w.setLayout(layout)
        self.setWidget(w)
        return

    @property
    def memory_mapping_str(self) -> None:
        """
        Generator for the string view model
        """
        for entry in self.__memory_mapping:
            yield str(entry)

    def updateView(self) -> bool:
        """
        Refresh the view
        """
        self.model.setStringList(self.memory_mapping_str)
        return True

    @property
    def maps(self) -> List[MemorySection]:
        """
        Exports the memory mapping to a format usable for Unicorn
        """
        self.__maps = self.__memory_mapping[::]
        return self.__maps

    def onAddSectionButtonClicked(self) -> None:
        """
        Callback associated with the click of the "Add Section" button
        """
        self.add_or_edit_section_popup()
        return

    def onDeleteSectionButtonClicked(self) -> None:
        """
        Callback associated with the click of the "Remove Section" button
        """
        idx = self.view.currentIndex()
        line_content = idx.data()
        for i, sect in enumerate(self.__memory_mapping):
            if line_content == str(sect):
                if self.__memory_mapping[i].name in (".text", ".data", ".stack"):
                    print("cannot delete required section '{}'".format(
                        self.__memory_mapping[i].name))
                    break
                del self.__memory_mapping[i]
                self.updateView()
                break
        return

    def add_or_edit_section_popup(self) -> None:
        """
        Popup that present a form with all info to submit to create a new section
        """
        msgbox = QMessageBox(self)
        wid = QWidget()

        name = QLabel("Name")
        nameEdit = QLineEdit()

        startAddress = QLabel("Start Address (hex)")
        startAddressEdit = QLineEdit()

        size = QLabel("Size (hex)")
        sizeEdit = QLineEdit()

        perm = QLabel("Permissions")
        permCheck = QWidget()
        permCheckLayout = QHBoxLayout()
        perm_read_btn = QCheckBox("R")
        perm_write_btn = QCheckBox("W")
        perm_exec_btn = QCheckBox("X")
        permCheckLayout.addWidget(perm_read_btn)
        permCheckLayout.addWidget(perm_write_btn)
        permCheckLayout.addWidget(perm_exec_btn)
        permCheck.setLayout(permCheckLayout)

        grid = QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(name, 1, 0)
        grid.addWidget(nameEdit, 1, 1)

        grid.addWidget(startAddress, 2, 0)
        grid.addWidget(startAddressEdit, 2, 1)

        grid.addWidget(size, 3, 0)
        grid.addWidget(sizeEdit, 3, 1)

        grid.addWidget(perm, 4, 0)
        grid.addWidget(permCheck, 4, 1)

        msgbox.setLayout(grid)
        msgbox.setGeometry(300, 300, 350, 300)

        msgbox.setWindowTitle("Add/edit section")
        layout = msgbox.layout()
        wid.setLayout(grid)
        wid.setMinimumWidth(400)
        layout.addWidget(wid)

        msgbox.setStandardButtons(
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)

        ret = msgbox.exec()
        if ret == QMessageBox.StandardButton.Ok:
            section_name = nameEdit.text()
            section_address = int(startAddressEdit.text(), 16)
            section_size = int(sizeEdit.text(), 16)
            section_perm = []
            if perm_read_btn.isChecked():
                section_perm.append("READ")
            if perm_write_btn.isChecked():
                section_perm.append("WRITE")
            if perm_exec_btn.isChecked():
                section_perm.append("EXEC")
            section = MemorySection(
                section_name, section_address, section_size, "|".join(section_perm))
            self.__memory_mapping.append(section)
            self.updateView()
        return
