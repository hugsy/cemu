from __future__ import annotations

import typing

from PyQt6.QtCore import Qt, QVariant
from PyQt6.QtGui import QFont, QTextFormat
from PyQt6.QtWidgets import (QDockWidget, QFrame, QHBoxLayout, QLabel,
                             QTextEdit, QVBoxLayout, QWidget)

import cemu.core
from cemu.const import COMMENT_MARKER

if typing.TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow

from ..utils import assemble, get_cursor_position
from .highlighter import Highlighter


class CodeEdit(QTextEdit):
    def __init__(self, parent):
        super(CodeEdit, self).__init__(parent)
        self.cursorPositionChanged.connect(self.UpdateHighlightedLine)
        self.setFont(QFont('Courier', 11))
        self.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        return

    def UpdateHighlightedLine(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(
            QTextFormat.Property.FullWidthSelection, QVariant(True))
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection, ])
        return


class AssemblyView(QTextEdit):
    def __init__(self, parent, editor):
        super().__init__(parent)
        self.rootWindow = parent.rootWindow
        self.setReadOnly(True)
        self.setFont(QFont('Courier', 11))
        self.setFixedWidth(140)
        self.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.setStyleSheet("background-color: rgb(211, 211, 211);")
        self.__editor = editor
        self.__editor.textChanged.connect(self.__update_assembly_code)
        return

    def __update_assembly_code(self):
        lines = self.__editor.toPlainText().splitlines()
        nb_lines = len(lines)
        bytecode_lines = ["", ]*nb_lines
        old_code = ""

        for idx in range(nb_lines):
            curline = lines[idx].strip()
            if not curline or curline.startswith(COMMENT_MARKER):
                bytecode_lines[idx] = "\n"
                continue

            asm = "\n".join(lines[:idx+1])
            code, _ = assemble(asm)
            if len(code) > len(old_code):
                new_code = code[len(old_code):]
                new_line = " ".join(["%.02x" % x for x in new_code])
                old_code = code
                bytecode_lines[idx] = new_line

        self.setText("\n".join(bytecode_lines))
        return


class CodeWithAssemblyFrame(QFrame):
    def __init__(self, parent: CodeEditorFrame):
        super().__init__(parent)
        self.rootWindow = parent.rootWindow
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
    def __init__(self, parent: CodeWidget):
        super().__init__(parent)
        self.rootWindow = parent.rootWindow
        inner_frame = CodeWithAssemblyFrame(self)
        self.editor = inner_frame.code_editor
        self.highlighter = Highlighter(self.editor, "asm")
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.addWidget(inner_frame)
        return


class CodeWidget(QDockWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__("Code View", parent)
        self.parentWindow = parent
        self.rootWindow: CEmuWindow = parent.rootWindow
        self.code_editor_frame = CodeEditorFrame(self)
        self.editor: CodeEdit = self.code_editor_frame.editor
        self.editor.cursorPositionChanged.connect(self.onCursorPositionChanged)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        self.widget_title_label = QLabel("Code (Line:1 Column:1)")
        layout.addWidget(self.widget_title_label)
        layout.addWidget(self.code_editor_frame)
        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)
        return

    def onCursorPositionChanged(self):
        self.UpdateTitleLabel()
        return

    def UpdateTitleLabel(self):
        row_num, col_num = get_cursor_position(self.editor)
        self.widget_title_label.setText(
            f"Code (Line:{row_num+1} Column:{col_num+1})")
        return

    def getCleanContent(self) -> str:
        """
        Returns the content of the Code widget as a byte array or string.
        """

        def remove_comments(lines: list[str]) -> list[str]:
            clean = []
            for line in lines:
                line = line.strip()
                if line.startswith(COMMENT_MARKER):
                    # ignore line comments
                    continue
                if "#" in line:
                    # strip everything *after* the `#`
                    line = line[: line.find("#")]
                clean.append(line)
            return clean

        def parse_syscalls(lines: list[str]) -> list[str]:
            parsed = []
            syscalls = cemu.core.context.architecture.syscalls
            syscall_names = syscalls.keys()
            for line in lines:
                for sysname in syscall_names:
                    pattern = f"__NR_SYS_{sysname}"
                    if pattern in line:
                        line = line.replace(pattern, str(syscalls[sysname]))
                parsed.append(line)
            return parsed

        code: str = self.editor.toPlainText()
        if not code:
            return ""

        lines: list[str] = code.splitlines()

        lines = remove_comments(lines)

        lines = parse_syscalls(lines)

        return '\n'.join(lines)
