import enum
import pathlib
from typing import Optional

import unicorn

MemoryLayoutEntryType = tuple[str, int, int, str, Optional[pathlib.Path]]

MEMORY_FIELD_SEPARATOR = "|"


class MemoryPermission(enum.IntFlag):
    """Abstract class for memory permission."""

    NONE = 0
    EXECUTE = 1
    WRITE = 2
    READ = 4
    ALL = EXECUTE | READ | WRITE

    def to_string(self) -> str:
        perm = []
        if self & MemoryPermission.READ:
            perm.append("read")
        if self & MemoryPermission.WRITE:
            perm.append("write")
        if self & MemoryPermission.EXECUTE:
            perm.append("exec")
        return MEMORY_FIELD_SEPARATOR.join(perm)

    __str__ = to_string

    @property
    def readable(self):
        return self & MemoryPermission.READ

    r = readable

    @property
    def writable(self):
        return self & MemoryPermission.WRITE

    w = writable

    @property
    def executable(self):
        return self & MemoryPermission.EXECUTE

    x = executable

    @staticmethod
    def from_string(perm: str) -> "MemoryPermission":
        perm_obj = MemoryPermission.NONE

        for block in map(str.lower, perm.split(MEMORY_FIELD_SEPARATOR)):
            block = block.strip()
            if block == "read":
                perm_obj |= MemoryPermission.READ
            elif block == "write":
                perm_obj |= MemoryPermission.WRITE
            elif block == "exec":
                perm_obj |= MemoryPermission.EXECUTE
            else:
                raise ValueError(f"Unsupported value {block}")

        return perm_obj

    def unicorn(self) -> int:
        """Get the integer value as used by `unicorn`

        Returns:
            int: _description_
        """
        perm_int = 0
        if self & MemoryPermission.READ:
            perm_int += unicorn.UC_PROT_READ
        return perm_int


class MemorySection:
    """Abstraction class for memory section"""

    def __init__(
        self,
        name: str,
        addr: int,
        size: int,
        perm: str,
        data_file: Optional[pathlib.Path] = None,
    ):
        if addr < 0 or addr >= 2**64:
            raise ValueError("address")

        if len(name.strip()) == 0:
            raise ValueError("name")

        if size < 0:
            raise ValueError("size")

        self.name = name.strip().lower()
        self.address = addr
        self.size = size
        self.permission = MemoryPermission.from_string(perm)
        self.file_source = None
        self.content = None
        if data_file and data_file.is_file():
            self.file_source = data_file
            self.content = data_file.open("rb").read()
        return

    @property
    def end(self):
        return self.address + self.size - 1

    def __str__(self) -> str:
        return (
            f"MemorySection([{self.address:#x}-{self.end:#x}], "
            f"name='{self.name:s}', "
            f"permission={str(self.permission)})"
        )

    def __contains__(self, addr: int) -> bool:
        """`in` operator overload

        Args:
            addr (int): _description_

        Returns:
            bool: _description_
        """
        return self.address <= addr <= self.end

    def overlaps(self, other: "MemorySection") -> bool:
        """Indicates whether this memory section overlaps another

        Args:
            other (MemorySection): _description_

        Returns:
            bool: _description_
        """
        return self.address in other or other.address in self
