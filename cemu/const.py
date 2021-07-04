import os

PROGNAME            = 'cemu'
AUTHOR              = 'hugsy'
EMAIL               = 'hugsy+github@blah.cat'
VERSION             = '0.6'
URL                 = f'https://github.com/{AUTHOR}/{PROGNAME}'
ISSUE_LINK          = f'https://github.com/{AUTHOR}/{PROGNAME}/issues'
RELEASE_LINK        = '{URL}/archive/{VERSION}.tar.gz'
LICENSE             = 'MIT'
DESCRIPTION         = '''Cemu is a simple assembly/dissembly/emulation IDE that provides an easy Plug-n-Play environment to start playing with many architectures (currently supports x86-{32,64}, ARM, AARCH64, MIPS, SPARC).'''
HOME                = os.path.expanduser("~")
PKG_PATH            = os.path.dirname(os.path.realpath(__file__))
ICON_PATH           = os.sep.join([PKG_PATH, "img", "icon.png"])
EXAMPLE_PATH        = os.sep.join([PKG_PATH, "examples"])
TEMPLATE_PATH       = os.sep.join([PKG_PATH, "templates"])
TITLE               = "CEmu - Cheap Emulator v.{}".format(VERSION)
COMMENT_MARKER      = ";;;"
PROPERTY_MARKER     = "@@@"
TEMPLATE_CONFIG     = os.sep.join([TEMPLATE_PATH, "cemu.ini"])
CONFIG_FILEPATH     = os.sep.join([HOME, ".cemu.ini"])
