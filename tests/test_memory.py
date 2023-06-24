import pytest
import unittest

from cemu.memory import MemoryPermission


class EmulationTestMemoryBasic(unittest.TestCase):
    def test_memory_conversion_from_string(self):
        assert MemoryPermission.from_string("Read") == MemoryPermission.READ
        assert MemoryPermission.from_string("wRIte") == MemoryPermission.WRITE
        assert MemoryPermission.from_string("exeC") == MemoryPermission.EXECUTE
        assert (
            MemoryPermission.from_string("Read|wRIte|wRIte")
            == MemoryPermission.READ | MemoryPermission.WRITE
        )
        assert MemoryPermission.from_string("Read|wRIte|exec") == MemoryPermission.ALL

        with pytest.raises(ValueError) as _:
            MemoryPermission.from_string("Read|wRIte|AAA")

    def test_memory_conversion_from_windows(self):
        assert MemoryPermission.from_windows(0x01) == MemoryPermission.NONE
        assert MemoryPermission.from_windows(0x02) == MemoryPermission.READ
        assert (
            MemoryPermission.from_windows(0x04)
            == MemoryPermission.READ | MemoryPermission.WRITE
        )
        assert (
            MemoryPermission.from_windows(0x08)
            == MemoryPermission.READ | MemoryPermission.WRITE
        )
        assert MemoryPermission.from_windows(0x10) == MemoryPermission.EXECUTE
        assert (
            MemoryPermission.from_windows(0x20)
            == MemoryPermission.EXECUTE | MemoryPermission.READ
        )
        assert MemoryPermission.from_windows(0x40) == (
            MemoryPermission.READ | MemoryPermission.WRITE | MemoryPermission.EXECUTE
        )
        assert MemoryPermission.from_windows(0x80) == (
            MemoryPermission.READ | MemoryPermission.WRITE | MemoryPermission.EXECUTE
        )

        with pytest.raises(NotImplementedError) as _:
            MemoryPermission.from_windows(0x100)

        with pytest.raises(ValueError) as _:
            MemoryPermission.from_windows(0x41414141)
