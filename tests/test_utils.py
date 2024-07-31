from cemu.arch import Architecture, Endianness, is_x86_64
import cemu.utils


def test_get_metadata_from_stream():
    raw = r"""
    ;;; @@@architecture x86_64
    ;;; @@@endianness little
    """
    res = cemu.utils.get_metadata_from_stream(raw)
    assert res and len(res) == 2
    assert isinstance(res[0], Architecture)
    assert is_x86_64(res[0])
    assert isinstance(res[1], Endianness)
    assert res[1] == Endianness.LITTLE_ENDIAN


def test_generate_random_string():
    pass


def test_ishex():
    pass


def test_assemble_file():
    pass


def test_assemble():
    pass


def test_disassemble_file():
    pass


def test_disassemble():
    pass


def test_format_address():
    pass


def test_hexdump():
    pass
