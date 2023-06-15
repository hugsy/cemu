from __future__ import annotations

import os
import typing

from PyQt6.QtCore import Qt, QVariant
from PyQt6.QtGui import QFont, QTextFormat
from PyQt6.QtWidgets import (
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import cemu.core
from cemu.const import (
    COMMENT_MARKER,
    DEFAULT_ASSEMBLY_VIEW_FONT,
    DEFAULT_ASSEMBLY_VIEW_FONT_SIZE,
    DEFAULT_CODE_VIEW_FONT,
    DEFAULT_CODE_VIEW_FONT_SIZE,
)
from cemu.log import error

if typing.TYPE_CHECKING:
    from cemu.ui.main import CEmuWindow

from ..utils import assemble
from .highlighter import Highlighter
from .utils import get_cursor_position


class CodeEdit(QTextEdit):
    def __init__(self, parent):
        super(CodeEdit, self).__init__(parent)
        self.cursorPositionChanged.connect(self.UpdateHighlightedLine)
        self.setFont(
            QFont(DEFAULT_CODE_VIEW_FONT, pointSize=DEFAULT_CODE_VIEW_FONT_SIZE)
        )
        self.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        return

    def UpdateHighlightedLine(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(
            QTextFormat.Property.FullWidthSelection, QVariant(True)
        )
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections(
            [
                selection,
            ]
        )
        return


class AssemblyView(QTextEdit):
    def __init__(self, parent, editor: CodeEdit):
        super().__init__(parent)
        self.rootWindow = parent.rootWindow
        self.setReadOnly(True)
        self.setFont(QFont(DEFAULT_ASSEMBLY_VIEW_FONT, DEFAULT_ASSEMBLY_VIEW_FONT_SIZE))
        self.setFixedWidth(140)
        self.setFrameStyle(QFrame.Shape.Panel | QFrame.Shape.NoFrame)
        self.setStyleSheet("background-color: rgb(211, 211, 211);")
        self.editor = editor
        self.editor.textChanged.connect(self.update_assembly_code_pane)
        self.__last_assembly_error_msg = ""
        return

    def update_assembly_code_pane(self):
        #
        # Execute only on line return
        #
        text: str = self.editor.toPlainText()
        cur: int = self.editor.textCursor().position()
        if cur < 1 or text[cur - 1] != os.linesep:
            return

        #
        # TODO add switch "Live Preview"
        #
        pane_width = self.width() // 10
        lines: list[str] = text.splitlines()
        bytecode_lines: list[str] = [
            "",
        ] * pane_width
        assembly_failed_lines: list[int] = []

        for i in range(len(lines)):
            try:
                line = lines[i].strip()
                if not line:
                    bytecode_lines[i] = ""
                    continue

                insns = assemble(line)
                insn = insns[0]
                bytecode = " ".join([f"{b:02x}" for b in insn.bytes])
                if len(bytecode) > (pane_width - 3):
                    bytecode_lines[i] = bytecode[: pane_width - 3] + "..."
                else:
                    bytecode_lines[i] = bytecode

            except Exception:
                assembly_failed_lines.append(i)
                bytecode_lines[i] = ""

        if assembly_failed_lines:
            msg = (
                f"Failed to assemble lines {', '.join(map(str, assembly_failed_lines))}"
            )
            if msg != self.__last_assembly_error_msg:
                error(msg)
                self.__last_assembly_error_msg = msg

        self.setText(os.linesep.join(bytecode_lines))
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
        self.editor.textChanged.connect(self.onUpdateText)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        self.widget_title_label = QLabel("Code (Line:1 Column:1)")
        layout.addWidget(self.widget_title_label)
        layout.addWidget(self.code_editor_frame)
        widget = QWidget(self)
        widget.setLayout(layout)
        self.setWidget(widget)
        return

    def onUpdateText(self):
        cemu.core.context.emulator.codelines = self.getCleanContent()
        return

    def onCursorPositionChanged(self):
        self.UpdateTitleLabel()
        return

    def UpdateTitleLabel(self):
        row_num, col_num = get_cursor_position(self.editor)
        self.widget_title_label.setText(f"Code (Line:{row_num+1} Column:{col_num+1})")
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

        def remove_empty_lines(lines: list[str]) -> list[str]:
            #
            # Bug in keystone: miscount of number of assembled insn
            #
            # Repro:
            # >>> ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            # >>> ks.asm("inc rax\n\n\ndec rbx", as_bytes=True)
            # (b'H\xff\xc0H\xff\xcb', 4)
            #
            # TODO report
            #
            return [x for x in lines if x]

        code: str = self.editor.toPlainText()
        if not code:
            return ""

        lines: list[str] = code.splitlines()
        lines = remove_comments(lines)
        lines = parse_syscalls(lines)
        lines = remove_empty_lines(lines)
        return os.linesep.join(lines)
