from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QFrame,
    QWidget,
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


def get_cursor_row_number_from_qtextedit(widget):
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return text[:pos].count('\n')


def get_cursor_column_number_from_qtextedit(widget):
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return len(text[:pos].split('\n')[-1])


class CodeInfoBarWidget(QWidget):
    def __init__(self, textedit_widget, *args, **kwargs):
        super(CodeInfoBarWidget, self).__init__()
        self.textedit_widget = textedit_widget
        layout = QHBoxLayout()
        self.label = QLabel("Line:1 Column:1")
        layout.addWidget(self.label)
        self.setLayout(layout)
        self.textedit_widget.cursorPositionChanged.connect(self.UpdateLabel)
        return


    def UpdateLabel(self):
        pos_x = get_cursor_row_number_from_qtextedit(self.textedit_widget) + 1
        pos_y = get_cursor_column_number_from_qtextedit(self.textedit_widget) + 1
        self.label.setText("Line:{:d} Column:{:d}".format(pos_x, pos_y))
        return


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
    def __init__(self, editor, arch):
        super(AssemblyView, self).__init__()
        self.setReadOnly(True)
        self.setFont(QFont('Courier', 11))
        self.setFixedWidth(140)
        self.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.setStyleSheet("background-color: rgb(211, 211, 211);")
        self.editor = editor
        self.arch = arch
        self.lines = {}
        self.editor.textChanged.connect(self.update_assembly_code)
        return

    def update_assembly_code(self):
        lines = self.editor.toPlainText().split('\n')
        current_row = get_cursor_row_number_from_qtextedit(self.editor)
        current_line = lines[current_row]
        if current_line.strip() == "":
            new_value = ""
        else:
            code, cnt = assemble(current_line, self.arch)
            new_value = "INVALID" if cnt != 1 else " ".join(["%.2x" % x for x in code])
        self.lines[current_row] = new_value
        self.setText("\n".join(self.lines.values()))
        return


class CodeEditorFrame(QFrame):
    def __init__(self, parent, arch):
        super(CodeEditorFrame, self).__init__(parent)

        # init code pane
        self.editor = CodeEdit(self)
        self.highlighter = Highlighter(self.editor, "asm")

        # compiled assembly pane
        self.assembly_view = AssemblyView(self.editor, arch)

        # info bar
        self.infobar = CodeInfoBarWidget(self.editor)

        # layout
        hbox = QHBoxLayout(self)
        hbox.setSpacing(0)
        hbox.addWidget(self.assembly_view)
        hbox.addWidget(self.editor)
        vbox = QVBoxLayout(self)
        vbox.setSpacing(0)
        vbox.addLayout(hbox)
        vbox.addWidget(self.infobar)
        # widget = QWidget(self)
        # widget.setLayout(vbox)
        return


class CodeWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__(parent)
        self.parent = self.parentWidget()
        self.emulator = self.parent.emulator
        self.log = self.parent.log
        self.code_editor_frame = CodeEditorFrame(parent=self, arch=self.parent.arch)
        self.editor = self.code_editor_frame.editor
        layout = QVBoxLayout()
        layout.addWidget( QLabel("Code") )
        layout.setSpacing(0)
        layout.addWidget(self.code_editor_frame)
        self.setLayout(layout)
        self.parser = CodeParser(self)
        return