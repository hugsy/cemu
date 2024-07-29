import enum
import os

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QMessageBox, QTextEdit

from cemu.log import dbg


def get_cursor_row_number(widget: QTextEdit) -> int:
    """Get the cursor row number from the QTextEdit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        int: _description_
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return text[:pos].count(os.linesep)


def get_cursor_column_number(widget: QTextEdit) -> int:
    """Get the cursor column number from the QTextEdit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        int: _description_
    """
    assert isinstance(widget, QTextEdit)
    pos = widget.textCursor().position()
    text = widget.toPlainText()
    return len(text[:pos].split(os.linesep)[-1])


def get_cursor_position(widget: QTextEdit) -> tuple[int, int]:
    """Returns the position of a cursor like (nb_row, nb_col) from a textedit widget

    Args:
        widget (QTextEdit): _description_

    Returns:
        tuple[int, int]: _description_
    """
    return (get_cursor_row_number(widget), get_cursor_column_number(widget))


class PopupType(enum.IntEnum):
    Information = 0
    Error = 1


def popup(msg: str, type: PopupType = PopupType.Error, title: str = ""):
    if type == PopupType.Information:
        icon = QMessageBox.Icon.Information
        title = f"Info - {title}"
    elif type == PopupType.Error:
        icon = QMessageBox.Icon.Critical
        title = f"Error - {title}"
    else:
        raise ValueError("invalid type")

    dbg(f"{title} - {msg}")
    QMessageBox(icon, title, msg, buttons=QMessageBox.StandardButton.Discard).exec()


def is_dark_mode(palette: QPalette):
    return palette.color(QPalette.ColorRole.Window).value() < 128


def brighten_color(hex_color: str, percent: float):
    # Remove the '#' if it exists
    hex_color = hex_color.lstrip('#')

    # Convert hex to RGB
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)

    # Increase each component by the given percentage
    r = min(255, int(r * (1 + percent / 100)))
    g = min(255, int(g * (1 + percent / 100)))
    b = min(255, int(b * (1 + percent / 100)))

    # Convert RGB back to hex
    return f'{r:02x}{g:02x}{b:02x}'


def hex_to_rgb(hex_color: str):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))


def is_red(hex_color: str):
    r, g, b = hex_to_rgb(hex_color)
    return r > g and r > b


def is_green(hex_color: str):
    r, g, b = hex_to_rgb(hex_color)
    return g > r and g > b


def is_blue(hex_color: str):
    r, g, b = hex_to_rgb(hex_color)
    return b > r and b > g
