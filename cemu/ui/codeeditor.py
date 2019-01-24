from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QFrame,
    QWidget
)

from PyQt5.QtGui import(
    QFont,
    QTextFormat,
)

from PyQt5.QtCore import(
    QVariant,
    Qt
)

#from PyQt5 import Qt

from cemu.parser import CodeParser

from .highlighter import Highlighter


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
        pos = self.textedit_widget.textCursor().position()
        text = self.textedit_widget.toPlainText()
        pos_x = text[:pos].count('\n') + 1
        pos_y = len(text[:pos].split('\n')[-1]) + 1
        self.label.setText("Line:{:d} Column:{:d}".format(pos_x, pos_y))
        return


class CodeEdit(QTextEdit):
    def __init__(self):
        super(CodeEdit, self).__init__()
        self.cursorPositionChanged.connect(self.UpdateHighlightedLine)
        return


    def UpdateHighlightedLine(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(self.palette().alternateBase())
        selection.format.setProperty(QTextFormat.FullWidthSelection, QVariant(True))
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection,])
        return


class CodeEditorFrame(QFrame):
    def __init__(self, *args, **kwargs):
        super(CodeEditorFrame, self).__init__()

        # init code pane
        self.editor = CodeEdit()
        self.editor.setFont(QFont('Courier', 11))
        self.editor.setFrameStyle(QFrame.Panel | QFrame.Plain)
        self.editor.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.highlighter = Highlighter(self.editor, "asm")

        # info bar
        self.infobar = CodeInfoBarWidget(self.editor)
        vbox = QVBoxLayout(self)
        vbox.setSpacing(0)
        vbox.addWidget(self.editor)
        vbox.addWidget(self.infobar)
        return


class CodeWidget(QWidget):
    def __init__(self, parent, *args, **kwargs):
        super(CodeWidget, self).__init__()
        self.parent = parent
        self.code_editor_frame = CodeEditorFrame()
        self.editor = self.code_editor_frame.editor
        layout = QVBoxLayout()
        layout.addWidget( QLabel("Code") )
        layout.setSpacing(0)
        layout.addWidget(self.code_editor_frame)
        self.setLayout(layout)
        self.parser = CodeParser(self)
        return