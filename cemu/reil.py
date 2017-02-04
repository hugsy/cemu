import os
import sys

global reiluse
try:
    __import__('imp').find_module('pyopenreil')
    from pyopenreil.REIL import *
    from pyopenreil.utils import asm
    reiluse = True
except ImportError:
    reiluse = False
    pass


class Reil:
    def __init__(self, mode, *args, **kwargs):
        self.mode = mode
        self.reiluse = reiluse
        return

    def symprint(self,app):
        self.widget.Symrwidget.editor.append(app)
        return

    def entry(self):
        self.widget.Symrwidget.editor.clear()
        self.widget.commandWidget.stopButton.setDisabled(False)
        code = self.widget.codeWidget.getCleanCodeAsByte(as_string=True, parse_string=True)
        code = tuple(synt for synt in code.split('\n') if synt)
        if reiluse:
            try:
                viasyntax = asm.Reader(ARCH_X86,(code),addr = 0)
                store = CodeStorageTranslator(viasyntax)
                irl = store.get_func(0)
                for func in irl.bb_list: self.symprint(str(func).replace(" "*4," "))
            except (ReadError,OSError):
                self.symprint("An error occured when converting instructions into the symbolic form")
            return
        else:
            self.symprint("pyopenREIL does not exists")
        return
