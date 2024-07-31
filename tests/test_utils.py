def test_get_metadata_from_stream():
    import cemu.arch
    import cemu.utils

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
    pass


def test_ishex():
    import cemu.utils

    assert not cemu.utils.ishex("0Xasd")
    assert cemu.utils.ishex("0123")
    assert not cemu.utils.ishex("0123asd")
    assert not cemu.utils.ishex("0x!!0123asd")
    assert not cemu.utils.ishex("0123fff==")
    assert cemu.utils.ishex("0123abcdef")


def test_hexdump():
    pass
