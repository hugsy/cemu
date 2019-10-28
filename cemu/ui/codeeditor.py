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
from ..utils import assemble

from .highlighter import Highlighter


def get_cursor_row_number(widget):
    """
    Get the cursor row number from the QTextEdit widget
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return text[:pos].count('\n')


def get_cursor_column_number(widget):
    """
    Get the cursor column number from the QTextEdit widget
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return len(text[:pos].split('\n')[-1])


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
    def __init__(self, parent, editor, arch):
        super(AssemblyView, self).__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont('Courier', 11))
        self.setFixedWidth(140)
        self.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.setStyleSheet("background-color: rgb(211, 211, 211);")
        self.__editor = editor
        self.__arch = arch
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
            code, cnt = assemble(asm, self.__arch)
            if len(code) > len(old_code):
                new_code = code[len(old_code):]
                new_line = " ".join(["%.02x" % x for x in new_code])
                old_code = code
                bytecode_lines[idx] = new_line

        self.setText("\n".join(bytecode_lines))
        return


class CodeWithAssemblyFrame(QFrame):
    def __init__(self, parent, arch):
        super(CodeWithAssemblyFrame, self).__init__(parent)
        self.__code_widget = CodeEdit(self)
        self.__asm_widget = AssemblyView(self, self.__code_widget, arch)
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
    def __init__(self, parent, arch):
        super(CodeEditorFrame, self).__init__(parent)
        inner_frame = CodeWithAssemblyFrame(self, arch)
        self.editor = inner_frame.code_editor
        self.__highlighter = Highlighter(self.editor, "asm")

        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.addWidget(inner_frame)
        return


class CodeWidget(QDockWidget): #QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__(parent)
        self.parent = self.parentWidget()
        self.root = self.parent
        self.emulator = self.root.emulator
        self.log = self.root.log
        self.code_editor_frame = CodeEditorFrame(parent=self, arch=self.root.arch)
        self.editor = self.code_editor_frame.editor
        self.editor.cursorPositionChanged.connect(self.onCursorPositionChanged)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        self.widget_title_label = QLabel("Code (Line:1 Column:1)")
        layout.addWidget(self.widget_title_label)
        layout.addWidget(self.code_editor_frame)
        self.setLayout(layout)
        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)
        self.parser = CodeParser(self)
        return


    def onCursorPositionChanged(self):
        self.UpdateTitleLabel()
        return


    def UpdateTitleLabel(self):
        row_num = get_cursor_row_number(self.editor) + 1
        col_num = get_cursor_column_number(self.editor) + 1
        self.widget_title_label.setText("Code (Line:{:d} Column:{:d})".format(
            row_num,
            col_num
        ))
        return