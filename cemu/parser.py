import binascii
import sys


class CodeParser():
    """
    This class aims to parse the content of the CodeWidget.
    """

    def __init__(self, code_widget, *args, **kwargs):
        self.code_widget = code_widget
        self.emulator = self.code_widget.parent.parent.emulator
        return


    def getCleanCodeAsByte(self, as_string=False, parse_string=True):
        """
        Returns the content of the Code widget as a byte array.
        """
        code = self.code_widget.editor.toPlainText()
        if code is None or len(code)==0:
            return [] if not as_string else b""

        code = code.split("\n")
        if sys.version_info.major == 2:
            code = [bytes(x) for x in code]
        else:
            code = [bytes(x, encoding="utf-8") for x in code]

        # remove comments
        code = self.removeComments(code)

        # parse strings
        if parse_string:
            code = self.parseStringInCode(code)

        # parse syscalls
        code = self.parseSyscalls(code)

        if as_string:
            return b'\n'.join(code)

        return code


    def removeComments(self, code, as_string=False):
        """
        Returns the code pane content cleaned of all comments.
        """
        comment_tags = ["#", ";", "--",]
        clean = []
        for line in code:
            line = line.strip()
            if len(line)==0:
                continue
            c = line[0]
            if sys.version_info.major == 3:
                c = chr(line[0])
            if c in comment_tags:
                continue
            clean.append(line)

        if as_string:
            return b"\n".join(clean)

        return clean


    def parseStringInCode(self, code, as_string=False):
        """
        This function will search for every line of assembly for quote(")
        pattern and convert it as a hexadecimal number.
        """
        parsed = []
        arch = self.emulator.parent.arch

        for line in code:
            i = line.find(b'"')
            if i==-1:
                # no string
                parsed.append(line)
                continue

            j = line[i+1:].find(b'"')
            if j==-1:
                # unfinished string
                parsed.append(line)
                continue

            if j != arch.ptrsize:
                # incorrect size
                parsed.append(line)
                continue

            origstr = line[i+1:i+j+1]
            hexstr  = binascii.hexlify(origstr)
            newline = line.replace(b'"%s"'%origstr, b'0x%s'%hexstr)
            parsed.append(newline)

        if as_string:
            return b'\n'.join(parsed)

        return parsed


    def parseSyscalls(self, code):
        """
        Parse Linux syscalls like __NR_SYS_* based on the current architecture
        """

        parsed = []
        syscalls = self.emulator.parent.arch.syscalls
        syscall_names = syscalls.keys()
        for line in code:
            for sysname in syscall_names:
                pattern = b"__NR_SYS_%s" % sysname
                if pattern in line:
                    line = line.replace(pattern, b'%d'%syscalls[sysname])
            parsed.append(line)
        return parsed
