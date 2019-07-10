import os


PROGNAME            = 'cemu'
AUTHOR              = 'hugsy'
EMAIL               = 'hugsy+github@blah.cat'
VERSION             = '0.4'
URL                 = 'https://github.com/{}/{}'.format(AUTHOR, PROGNAME)
ISSUES              = 'https://github.com/{}/{}/issues'.format(AUTHOR, PROGNAME)
RELEASE_LINK        = '{}/archive/{}.tar.gz'.format(URL, VERSION)
LICENSE             = 'MIT'


WINDOW_SIZE        = (1600, 800)
PKG_PATH           = os.path.dirname(os.path.realpath(__file__))
ICON_PATH          = "{}/img/icon.png".format(PKG_PATH)
EXAMPLE_PATH       = "{}/examples".format(PKG_PATH)
TEMPLATE_PATH      = "{}/templates".format(PKG_PATH)
TITLE              = "CEmu - Cheap Emulator v.{}".format(VERSION)
HOME               = os.getenv("HOME")
COMMENT_MARKER     = ";;;"
PROPERTY_MARKER    = "@@@"
