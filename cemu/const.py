import os

from . import VERSION as cemu_version

WINDOW_SIZE        = (1600, 800)
PKG_PATH           = os.path.dirname(os.path.realpath(__file__))
ICON_PATH          = "{}/img/icon.png".format(PKG_PATH)
EXAMPLE_PATH       = "{}/examples".format(PKG_PATH)
TEMPLATE_PATH      = "{}/templates".format(PKG_PATH)
TITLE              = "CEmu - Cheap Emulator v.{}".format(cemu_version)
HOME               = os.getenv("HOME")
COMMENT_MARKER     = ";;;"
PROPERTY_MARKER    = "@@@"
