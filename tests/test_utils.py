import string
import pytest

import cemu.core
import cemu.utils
import cemu.arch


def test_get_metadata_from_stream():
    raw = r"""
    ;;; @@@architecture x86_64
    ;;; @@@endianness little
    """
    res = cemu.utils.get_metadata_from_stream(raw)
    assert res and len(res) == 2
    assert isinstance(res[0], cemu.arch.Architecture)
    assert cemu.arch.is_x86_64(res[0])
    assert isinstance(res[1], cemu.arch.Endianness)
    assert res[1] == cemu.arch.Endianness.LITTLE_ENDIAN


def test_generate_random_string():
    assert len(cemu.utils.generate_random_string(5)) == 5
    assert isinstance(cemu.utils.generate_random_string(5), str)
    with pytest.raises(ValueError):
        cemu.utils.generate_random_string(-5)

    res = cemu.utils.generate_random_string(500, charset=string.ascii_letters)
    assert all(filter(lambda x: x in string.ascii_letters, res))


def test_ishex():
    assert not cemu.utils.ishex("0Xasd")
    assert cemu.utils.ishex("0123")
    assert not cemu.utils.ishex("0123asd")
    assert not cemu.utils.ishex("0x!!0123asd")
    assert not cemu.utils.ishex("0123fff==")
    assert cemu.utils.ishex("0123abcdef")


def test_hexdump():
    cemu.core.context = cemu.core.GlobalContext()
    cemu.core.context.architecture = cemu.arch.Architectures.find("x86_32")
    assert cemu.utils.hexdump(b"aaaa") == "0x000000  61 61 61 61  aaaa"
    cemu.core.context.architecture = cemu.arch.Architectures.find("x86_64")
    assert cemu.utils.hexdump(b"aaaa") == "0x00000000000000  61 61 61 61  aaaa"

    with pytest.raises(ValueError):
        cemu.utils.hexdump(b"aaaa", separator="")

    assert cemu.utils.hexdump(b"\x41\x41\xff\xfe") == "0x00000000000000  41 41 FF FE  AA.."

    with pytest.raises(ValueError):
        cemu.utils.hexdump(b"A" * 0x20, alignment=3)

    assert cemu.utils.hexdump(b"\x41\x41\xff\xfe", base=0x41414141_41414141) == "0x4141414141414141  41 41 FF FE  AA.."
    res = cemu.utils.hexdump(b"A" * 0x20, base=0x41414141_41414141).splitlines()

    assert len(res) == 2
    assert res[0] == "0x4141414141414141  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA"
    assert res[1] == "0x4141414141414151  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA"
