import pathlib
import cemu
import cemu.arch
import cemu.core

assert cemu.__package__
assert len(cemu.__package__) >= 1

CURRENT_FILE = pathlib.Path(__file__)
CURRENT_DIR = CURRENT_FILE.parent
CEMU_PACKAGE_ROOT = CURRENT_DIR / "../src/cemu"
CEMU_EXAMPLES_FOLDER = CEMU_PACKAGE_ROOT / "examples"


def test_endianness_basic():
    assert int(cemu.arch.Endianness.LITTLE_ENDIAN) == 1
    assert int(cemu.arch.Endianness.BIG_ENDIAN) == 2
    assert str(cemu.arch.Endianness.BIG_ENDIAN) == "Big Endian"
    assert str(cemu.arch.Endianness.LITTLE_ENDIAN) == "Little Endian"


def test_syntax_basic():
    assert int(cemu.arch.Syntax.INTEL) == 1
    assert str(cemu.arch.Syntax.INTEL) == "INTEL"
    assert int(cemu.arch.Syntax.ATT) == 2
    assert str(cemu.arch.Syntax.ATT) == "ATT"


def test_architecture_manager():
    archs = cemu.arch.Architectures
    assert isinstance(archs, dict)


def test_assemble_file():
    cemu.core.context = cemu.core.GlobalContext()

    def parse_syscalls(lines: list[str]) -> list[str]:
        parsed = []
        assert cemu.core.context
        syscalls = cemu.core.context.architecture.syscalls
        syscall_names = syscalls.keys()
        for line in lines:
            for sysname in syscall_names:
                pattern = f"__NR_SYS_{sysname}"
                if pattern in line:
                    line = line.replace(pattern, str(syscalls[sysname]))
            parsed.append(line)
        return parsed

    # Values:
    # ['generic', 'x86_32', 'x86_64', 'x86', 'arm', 'aarch64', 'mips', 'mips64', 'sparc', 'sparc64']

    for tc in (
        "aarch64",
        "arm",
        "mips",
        "sparc",
        "x86_32",
        "x86_64",
    ):
        cemu.core.context.architecture = cemu.arch.Architectures.find(tc)
        fpath = CEMU_EXAMPLES_FOLDER / f"{tc}_sys_exec_bin_sh.asm"
        code = ";".join(parse_syscalls([x for x in fpath.read_text().splitlines() if not x.startswith(";;; ")]))
        insns = cemu.arch.assemble(code)
        assert len(insns) > 0


def test_disassemble_file():
    cemu.core.context = cemu.core.GlobalContext()

    # Values:
    # ['generic', 'x86_32', 'x86_64', 'x86', 'arm', 'aarch64', 'mips', 'mips64', 'sparc', 'sparc64']

    for tc in ("arm", "sparc", "x86"):
        cemu.core.context.architecture = cemu.arch.Architectures.find(tc)
        insns = cemu.arch.disassemble_file(CEMU_EXAMPLES_FOLDER / f"{tc}_nops.raw")
        assert len(insns) == 10


def test_disassemble():
    cemu.core.context = cemu.core.GlobalContext()
    insns = cemu.arch.disassemble(b"\xcc")
    assert len(insns) == 1
