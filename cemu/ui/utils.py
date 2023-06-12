import enum
import os

from PyQt6.QtWidgets import QErrorMessage, QTextEdit


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


def popup(msg: str, type: PopupType = PopupType.Error):
    if type == PopupType.Error:
        dialog = QErrorMessage()
    else:
        raise ValueError("invalid type")

    dialog.showMessage(msg)
