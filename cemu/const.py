import os


PROGNAME            = 'cemu'
AUTHOR              = 'hugsy'
EMAIL               = 'hugsy+github@blah.cat'
VERSION             = '0.5'
URL                 = 'https://github.com/{}/{}'.format(AUTHOR, PROGNAME)
ISSUE_LINK          = 'https://github.com/{}/{}/issues'.format(AUTHOR, PROGNAME)
RELEASE_LINK        = '{}/archive/{}.tar.gz'.format(URL, VERSION)
LICENSE             = 'MIT'

HOME               = os.getenv("HOME")
PKG_PATH           = os.path.dirname(os.path.realpath(__file__))
ICON_PATH          = os.sep.join([PKG_PATH, "img", "icon.png"])
EXAMPLE_PATH       = os.sep.join([PKG_PATH, "examples"])
TEMPLATE_PATH      = os.sep.join([PKG_PATH, "templates"])
TITLE              = "CEmu - Cheap Emulator v.{}".format(VERSION)
COMMENT_MARKER     = ";;;"
PROPERTY_MARKER    = "@@@"

TEMPLATE_CONFIG    = os.sep.join([TEMPLATE_PATH, "cemu.ini"])
CONFIG_FILEPATH    = os.sep.join([HOME, ".cemu.ini"])
