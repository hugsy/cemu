import pathlib
import enum

from typing import Optional, Tuple

import cemu.core

MemoryLayoutEntryType = Tuple[str, int, int, str, Optional[pathlib.Path]]


class Permission(enum.Flag):
    """Representation of Linux permission."""
    NONE = 0
    EXECUTE = 1
    WRITE = 2
    READ = 4
    ALL = EXECUTE | READ | WRITE

    def __str__(self) -> str:
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str


class MemoryPermission:

    def __init__(self, perm: str):
        self.r, self.w, self.x = False, False, False
        self.parse(perm)
        return

    def parse(self, perm: str) -> None:
        if perm.strip().lower() == "all":
            self.r = self.w = self.x = True
            return

        for p in perm.split("|"):
            p = p.strip().lower()
            if p == "read":
                self.r = True
            elif p == "write":
                self.w = True
            elif p == "exec":
                self.x = True
        return

    def __str__(self) -> str:
        m = []
        if self.r:
            m.append("READ")
        if self.w:
            m.append("WRITE")
        if self.x:
            m.append("EXEC")
        return "|".join(m)

    def short(self) -> str:
        m = []
        if self.r:
            m.append("r")
        if self.w:
            m.append("w")
        if self.x:
            m.append("x")
        return "".join(m)


class MemorySection:
    def __init__(self, name: str, addr: int, size: int, perm: str, data_file: Optional[pathlib.Path] = None):
        self.name = name
        self.address = addr
        self.size = size
        self.permission = MemoryPermission(perm)
        self.file_source = None
        self.content = None
        if data_file and data_file.is_file():
            self.file_source = data_file
            self.content = data_file.open("rb").read()
        return

    def __str__(self) -> str:
        return "[0x{:x}-0x{:x}] {:s} ({:s})".format(self.address, self.address+self.size-1, self.name, self.permission.short())

    def export(self) -> MemoryLayoutEntryType:
        return (self.name, self.address, self.size, str(self.permission), self.file_source)

    def __contains__(self, addr: int) -> bool:
        return self.address <= addr < self.address + self.size
