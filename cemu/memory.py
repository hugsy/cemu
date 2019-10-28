import os

from typing import List, Tuple, Any
MemoryLayoutEntryType = Tuple[str, int, int, str, Any]


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
            if p == "read": self.r = True
            elif p == "write": self.w = True
            elif p == "exec": self.x = True
        return


    def __str__(self) -> str:
        m = []
        if self.r: m.append("READ")
        if self.w: m.append("WRITE")
        if self.x: m.append("EXEC")
        return "|".join(m)


    def short(self) -> str:
        m = []
        if self.r: m.append("r")
        if self.w: m.append("w")
        if self.x: m.append("x")
        return "".join(m)




class MemorySection:
    def __init__(self, name: str, addr: int, size: int, perm: str, __file=None):
        self.name = name
        self.address = addr
        self.size = size
        self.permission = MemoryPermission(perm)
        self.file_source = __file
        self.content = None
        if __file and os.access(__file, os.R_OK):
            self.content = open(__file, "rb").read()
        return


    def __str__(self) -> str:
        return "[0x{:x}-0x{:x}] {:s} ({:s})".format(self.address, self.address+self.size-1, self.name, self.permission.short())


    def export(self) -> MemoryLayoutEntryType:
        return [self.name, self.address, self.size, str(self.permission), self.file_source]


    def __contains__(self, addr: int) -> bool:
        return self.address <= addr < self.address + self.size
