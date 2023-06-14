import pathlib

DEBUG = True

PROGNAME = "cemu"
AUTHOR = "hugsy"
EMAIL = "hugsy+github@blah.cat"
VERSION = "0.7"
URL = f"https://github.com/{AUTHOR}/{PROGNAME}"
ISSUE_LINK = f"https://github.com/{AUTHOR}/{PROGNAME}/issues"
RELEASE_LINK = f"{URL}/archive/{VERSION}.tar.gz"
LICENSE = "MIT"
DESCRIPTION = (
    """Cemu is a simple assembly/dissembly/emulation IDE that provides an easy """
    """Plug-n-Play environment to start playing with many architectures (currently """
    """supports x86-{32,64}, ARM, AARCH64, MIPS, MIPS64, SPARC and PPC)."""
)
HOME = pathlib.Path("").home()
PKG_PATH = pathlib.Path(__file__).absolute().parent
ICON_PATH = pathlib.Path(PKG_PATH) / "img/icon.png"
EXAMPLE_PATH = pathlib.Path(PKG_PATH) / "examples"
TEMPLATE_PATH = pathlib.Path(PKG_PATH) / "templates"
STYLE_PATH = pathlib.Path(PKG_PATH) / "styles"
SYSCALLS_PATH = pathlib.Path(PKG_PATH) / "syscalls"
PLUGINS_PATH = pathlib.Path(PKG_PATH) / "plugins"
TITLE = f"CEmu - Cheap Emulator v.{VERSION}"
COMMENT_MARKER = ";;;"
PROPERTY_MARKER = "@@@"
TEMPLATE_CONFIG = TEMPLATE_PATH / "cemu.ini"
CONFIG_FILEPATH = HOME / ".cemu.ini"
DEFAULT_STYLE_PATH = STYLE_PATH / "default.qss"

LOG_INSERT_TIMESTAMP = False
LOG_DEFAULT_TIMESTAMP_FORMAT = "%Y/%m/%d - %H:%M:%S"

DEFAULT_REGISTER_VIEW_REGISTER_FONT: str = "Courier"
DEFAULT_REGISTER_VIEW_REGISTER_FONT_SIZE: int = 11
DEFAULT_REGISTER_VIEW_CHANGED_REGISTER_COLOR: str = "red"

DEFAULT_CODE_VIEW_FONT: str = "Courier"
DEFAULT_CODE_VIEW_FONT_SIZE: int = 11

DEFAULT_ASSEMBLY_VIEW_FONT: str = "Courier"
DEFAULT_ASSEMBLY_VIEW_FONT_SIZE: int = 11

DEFAULT_MEMORY_VIEW_FONT: str = "Courier"
DEFAULT_MEMORY_VIEW_FONT_SIZE: int = 10
DEFAULT_MEMORY_VIEW_CHUNK_SIZE: int = 256

DEFAULT_FONT: str = "Courier"
DEFAULT_FONT_SIZE: int = 10
