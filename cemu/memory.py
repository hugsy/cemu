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

    @staticmethod
    def from_windows(protect: int) -> "MemoryPermission":
        """Converts region Protection values to a MemoryProtection

        Args:
            protect (int): _description_

        Raises:
            ValueError: if there's no match
            NotImplementedError: for PAGE_GUARD

        Returns:
            MemoryPermission: _description_
        """
        match protect:
            case 0x01:
                # PAGE_NOACCESS
                return MemoryPermission.NONE
            case 0x02:
                # PAGE_READONLY
                return MemoryPermission.READ
            case 0x04:
                # PAGE_READWRITE
                return MemoryPermission.READ | MemoryPermission.WRITE
            case 0x08:
                # PAGE_WRITECOPY
                return MemoryPermission.READ | MemoryPermission.WRITE
            case 0x10:
                # PAGE_EXECUTE
                return MemoryPermission.EXECUTE
            case 0x20:
                # PAGE_EXECUTE_READ
                return MemoryPermission.EXECUTE | MemoryPermission.READ
            case 0x40:
                # PAGE_EXECUTE_READWRITE
                return (
                    MemoryPermission.READ
                    | MemoryPermission.WRITE
                    | MemoryPermission.EXECUTE
                )
            case 0x80:
                # PAGE_EXECUTE_WRITECOPY
                return (
                    MemoryPermission.READ
                    | MemoryPermission.WRITE
                    | MemoryPermission.EXECUTE
                )
            case 0x100:
                raise NotImplementedError("PAGE_GUARD is not implemented")

        raise ValueError(f"Invalid value {protect}")

    def as_windows_str(self) -> str:
        """Converts region Protection values to a MemoryProtection

        Args:
            protect (int): _description_

        Raises:
            ValueError: if there's no match
            NotImplementedError: for PAGE_GUARD

        Returns:
            MemoryPermission: _description_
        """

        if self == MemoryPermission.NONE:
            return "PAGE_NOACCESS"

        if self == MemoryPermission.READ:
            return "PAGE_READONLY"

        if self == MemoryPermission.READ | MemoryPermission.WRITE:
            return "PAGE_READWRITE"

        if self == MemoryPermission.EXECUTE:
            return "PAGE_EXECUTE"

        if self == MemoryPermission.EXECUTE | MemoryPermission.READ:
            return "PAGE_EXECUTE_READ"

        if self == MemoryPermission.ALL:
            return "PAGE_EXECUTE_READWRITE"

        raise ValueError(f"Cannot convert value {int(self)}")

    def unicorn(self) -> int:
        """Get the integer value as used by `unicorn`

        Returns:
            int: the protection, as a value understandable for unicorn
        """
        if self == MemoryPermission.NONE:
            return unicorn.UC_PROT_NONE

        unicorn_permission = 0
        if self & MemoryPermission.READ:
            unicorn_permission |= unicorn.UC_PROT_READ

        if self & MemoryPermission.WRITE:
            unicorn_permission |= unicorn.UC_PROT_WRITE

        if self & MemoryPermission.EXECUTE:
            unicorn_permission |= unicorn.UC_PROT_EXEC

        return unicorn_permission


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
        self.file_source = data_file if data_file and data_file.is_file() else None
        return

    @property
    def end(self):
        return self.address + self.size - 1

    @property
    def content(self) -> Optional[bytes]:
        """Get the content from source file. This data will be used to populate the memory region

        Raises:
            AttributeError: if the file content exceeds the region size

        Returns:
            bytes: the file content
        """
        if not self.file_source:
            return None

        data = self.file_source.open("rb").read()
        if len(data) > self.size:
            raise AttributeError("Insufficient space")
        return data

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
