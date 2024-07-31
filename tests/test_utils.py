import cemu.arch


def test_get_metadata_from_stream():
    from cemu.utils import get_metadata_from_stream

    raw = r"""
    ;;; @@@architecture x86_64
    ;;; @@@endianness little
    """
    res = get_metadata_from_stream(raw)
    assert res and len(res) == 2
    assert isinstance(res[0], cemu.arch.Architecture)
    assert cemu.arch.is_x86_64(res[0])
    assert isinstance(res[1], cemu.arch.Endianness)
    assert res[1] == cemu.arch.Endianness.LITTLE_ENDIAN


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
