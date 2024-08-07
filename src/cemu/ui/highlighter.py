import time

from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QPalette
from pygments import highlight
from pygments.formatter import Formatter
from pygments.lexers import get_lexer_by_name

import cemu.log
from cemu.ui.utils import brighten_color, is_blue, is_red, is_dark_mode, is_green


class QFormatter(Formatter):
    def __init__(self, palette: QPalette):
        Formatter.__init__(self)
        self.data = []
        self.styles: dict[str, QTextCharFormat] = {}
        for token, style in self.style:
            qtf = QTextCharFormat()
            if style["color"]:
                style_color = style["color"]
                if is_dark_mode(palette):
                    if is_blue(style_color):
                        style_color = "3F81F0"
                    elif is_red(style_color):
                        style_color = "F92673"
                    elif is_green(style_color):
                        style_color = "20999D"
                    else:
                        style_color = brighten_color(style_color, 50)
                qtf.setForeground(self.hex2QColor(style_color))
            if style["bgcolor"]:
                qtf.setBackground(self.hex2QColor(style["bgcolor"]))
            if style["bold"]:
                qtf.setFontWeight(QFont.Weight.Bold)
            if style["italic"]:
                qtf.setFontItalic(True)
            if style["underline"]:
                qtf.setFontUnderline(True)
            self.styles[str(token)] = qtf

    def hex2QColor(self, color: str):
        red = int(color[0:2], 16)
        green = int(color[2:4], 16)
        blue = int(color[4:6], 16)
        return QColor(red, green, blue)

    def format(self, tokensource, outfile):
        self.data = []
        for ttype, value in tokensource:
            value_width = len(value)
            type_as_str = str(ttype)
            self.data.extend(
                [
                    self.styles[type_as_str],
                ]
                * value_width
            )


class Highlighter(QSyntaxHighlighter):
    def __init__(self, parent, mode):
        QSyntaxHighlighter.__init__(self, parent)
        self.tstamp = time.time()
        self.formatter = QFormatter(parent.palette())
        self.lexer = get_lexer_by_name(mode)
        return

    def highlightBlock(self, text):
        cb = self.currentBlock()
        pos = cb.position()
        doc = self.document()
        if not doc:
            cemu.log.dbg("Missing doc")
            return
        text = doc.toPlainText() + "\n"
        highlight(text, self.lexer, self.formatter)
        for i in range(len(text)):
            try:
                self.setFormat(i, 1, self.formatter.data[pos + i])
            except IndexError as ie:
                cemu.log.dbg(f"setFormat() failed, reason: {ie}")
                break
        self.tstamp = time.time()
        return
