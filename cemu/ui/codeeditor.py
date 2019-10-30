from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QFrame,
    QWidget,
    QDockWidget,
)

from PyQt5.QtGui import(
    QFont,
    QTextFormat,
)

from PyQt5.QtCore import(
    QVariant,
    Qt,
)

from ..parser import CodeParser
from ..utils import (
    assemble,
    get_cursor_position,
    get_cursor_row_number,
    get_cursor_column_number,
)

from .highlighter import Highlighter


class CodeEdit(QTextEdit):
    def __init__(self, parent):
        super(CodeEdit, self).__init__(parent)
        self.cursorPositionChanged.connect(self.UpdateHighlightedLine)
        self.setFont(QFont('Courier', 11))
        self.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        return


    def UpdateHighlightedLine(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(QTextFormat.FullWidthSelection, QVariant(True))
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection,])
        return


class AssemblyView(QTextEdit):
    def __init__(self, parent, editor):
        super(AssemblyView, self).__init__(parent)
        self.parent = self.parentWidget()
        self.root = self.parent.root
        self.setReadOnly(True)
        self.setFont(QFont('Courier', 11))
        self.setFixedWidth(140)
        self.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.setStyleSheet("background-color: rgb(211, 211, 211);")
        self.__editor = editor
        self.__editor.textChanged.connect(self.__update_assembly_code)
        return


    def __update_assembly_code(self):
        lines = self.__editor.toPlainText().split('\n')
        nb_lines = len(lines)
        bytecode_lines = ["",]*nb_lines
        old_code = ""

        for idx in range(nb_lines):
            curline = lines[idx].strip()
            if curline == "" or curline.startswith(";;;") or curline.startswith("#"):
                bytecode_lines[idx] = ""
                continue

            asm = "\n".join(lines[:idx+1])
            code, cnt = assemble(asm, self.root.arch)
            if len(code) > len(old_code):
                new_code = code[len(old_code):]
                new_line = " ".join(["%.02x" % x for x in new_code])
                old_code = code
                bytecode_lines[idx] = new_line

        self.setText("\n".join(bytecode_lines))
        return


class CodeWithAssemblyFrame(QFrame):
    def __init__(self, parent):
        super(CodeWithAssemblyFrame, self).__init__(parent)
        self.parent = self.parentWidget()
        self.root = self.parent.root
        self.__code_widget = CodeEdit(self)
        self.__asm_widget = AssemblyView(self, self.__code_widget)
        layout = QHBoxLayout(self)
        layout.setSpacing(0)
        layout.addWidget(self.__asm_widget)
        layout.addWidget(self.__code_widget)
        self.setLayout(layout)
        return

    @property
    def code_editor(self):
        return self.__code_widget


class CodeEditorFrame(QFrame):
    def __init__(self, parent):
        super(CodeEditorFrame, self).__init__(parent)
        self.parent = self.parentWidget()
        self.root = self.parent.root
        inner_frame = CodeWithAssemblyFrame(self)
        self.editor = inner_frame.code_editor
        self.__highlighter = Highlighter(self.editor, "asm")
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.addWidget(inner_frame)
        return


class CodeWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__("Code View", parent)
        self.parent = self.parentWidget()
        self.root = self.parent
        self.emulator = self.root.emulator
        self.log = self.root.log
        self.code_editor_frame = CodeEditorFrame(self)
        self.editor = self.code_editor_frame.editor
        self.editor.cursorPositionChanged.connect(self.onCursorPositionChanged)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        self.widget_title_label = QLabel("Code (Line:1 Column:1)")
        layout.addWidget(self.widget_title_label)
        layout.addWidget(self.code_editor_frame)
        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)
        self.parser = CodeParser(self)
        return


    def onCursorPositionChanged(self):
        self.UpdateTitleLabel()
        return


    def UpdateTitleLabel(self):
        row_num, col_num = get_cursor_position(self.editor)
        self.widget_title_label.setText("Code (Line:{:d} Column:{:d})".format(
            row_num+1,
            col_num+1
        ))
        return