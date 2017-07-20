import sys, traceback

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class StdoutRedirector:
    def __init__(self, write_func):
        self.write_func = write_func
        self.skip = False
        return

    def write(self, text):
        if not self.skip:
            self.write_func(text)
            QCoreApplication.processEvents()
            self.skip = not self.skip
        return


class PythonConsole(QTextEdit):
    def __init__(self, prompt='>>> ', startup_message='', parent=None):
        QTextEdit.__init__(self, parent)
        self.prompt = prompt
        self.history = []
        self.construct = []
        self.parent = parent
        self.startup_message = startup_message
        self.__locales = locals()
        self.__globals = globals()

        self.setWordWrapMode(QTextOption.WrapAnywhere)
        self.setUndoRedoEnabled(False)
        self.document().setDefaultFont(QFont("monospace", 10, QFont.Normal))
        self.setText(self.startup_message+"\n")
        self.newPrompt()
        return

    def appendPlainText(self, message):
        text = self.toPlainText()
        self.setText(text + message)
        return

    def newPrompt(self):
        prompt = '.' * len(self.prompt) if self.construct else self.prompt
        self.appendPlainText(prompt)
        self.moveCursor(QTextCursor.End)
        return

    def getCommand(self):
        doc = self.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        return curr_line.rstrip().lstrip(self.prompt)

    def setCommand(self, command):
        if self.getCommand() == command:
            return
        self.moveCursor(QTextCursor.End)
        self.moveCursor(QTextCursor.StartOfLine, QTextCursor.KeepAnchor)
        for i in range(len(self.prompt)):
            self.moveCursor(QTextCursor.Right, QTextCursor.KeepAnchor)
        self.textCursor().removeSelectedText()
        self.textCursor().insertText(command)
        self.moveCursor(QTextCursor.End)
        return

    def getConstruct(self, command):
        if self.construct:
            prev_command = self.construct[-1]
            self.construct.append(command)
            if not prev_command and not command:
                ret_val = '\n'.join(self.construct)
                self.construct = []
                return ret_val
            else:
                return ''
        else:
            if command and command[-1] == (':'):
                self.construct.append(command)
                return ''
            else:
                return command


    def add_last_command_to_history(self):
        command = self.getCommand().rstrip()
        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
        self.history_index = len(self.history)
        return

    def getPrevHistoryEntry(self):
        if self.history:
            self.history_index = max(0, self.history_index - 1)
            return self.history[self.history_index]
        return ''

    def getNextHistoryEntry(self):
        if self.history:
            hist_len = len(self.history)
            self.history_index = min(hist_len, self.history_index + 1)
            if self.history_index < hist_len:
                return self.history[self.history_index]
        return ''


    def get_current_position(self):
        return self.textCursor().columnNumber() - len(self.prompt)


    def move_cursor_to(self, position):
        self.moveCursor(QTextCursor.StartOfLine)
        for i in range(len(self.prompt) + position):
            self.moveCursor(QTextCursor.Right)
        return


    def run_command(self):
        command = self.getCommand()
        command = self.getConstruct(command)

        if command:
            self.appendPlainText("\n")
            try:
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                sys.stdout = StdoutRedirector(self.appendPlainText)
                sys.stderr = sys.stdout

                result = eval(command, self.__locales, self.__globals)
                if result is not None:
                    self.appendPlainText("{}\n".format(result))

            except SyntaxError:
                exec(command, self.__locales, self.__globals)

            except SystemExit:
                self.setText(self.startup_message+'\n')

            except Exception:
                traceback_lines = traceback.format_exc().split('\n')
                for i in (3,2,1,-1):
                    traceback_lines.pop(i)
                self.appendPlainText('\n'.join(traceback_lines)+'\n')

            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        self.newPrompt()
        return


    def enter_handle(self):
        self.run_command()
        self.add_last_command_to_history()
        return


    def home_handle(self):
        self.move_cursor_to(0)
        return


    def pageup_handle(self):
        return


    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Enter, Qt.Key_Return):
            self.enter_handle()
            return

        if event.key() == Qt.Key_Home:
            self.home_handle()
            return

        if event.key() == Qt.Key_PageUp:
            self.pageup_handle()
            return

        if event.key() in (Qt.Key_Left, Qt.Key_Backspace):
            if self.get_current_position() == 0:
                return

        if event.key() == Qt.Key_Up:
            self.setCommand(self.getPrevHistoryEntry())
            return

        if event.key() == Qt.Key_Down:
            self.setCommand(self.getNextHistoryEntry())
            return

        if event.key() == Qt.Key_D and event.modifiers() == Qt.ControlModifier:
            self.close()

        super(PythonConsole, self).keyPressEvent(event)
        return


    @property
    def emu(self):
        return self.parent.parent.emu


    @property
    def vm(self):
        return self.emu.vm


    @property
    def arch(self):
        return self.emu.arch
