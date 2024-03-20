#!/usr/bin/env python3

import pathlib
import sys
import os

import cemu.const
import cemu.core
import cemu.log


def setup_remote_debug(port: int = cemu.const.DEBUG_DEBUGPY_PORT):
    assert cemu.const.DEBUG
    import debugpy

    debugpy.listen(port)
    cemu.log.dbg("Waiting for debugger attach")
    debugpy.wait_for_client()
    cemu.log.dbg("Client connected, resuming session")


def main():
    if bool(os.getenv("DEBUG", False)) or "--debug" in sys.argv:
        cemu.const.DEBUG = True

    if cemu.const.DEBUG:
        cemu.log.register_sink(print)
        cemu.log.dbg("Starting in Debug Mode")

        if "--attach" in sys.argv:
            setup_remote_debug()

    if "--cli" in sys.argv:
        cemu.core.CemuCli(sys.argv)
        return

    cemu.core.CemuGui(sys.argv)
    return


if __name__ == "__main__":
    path = pathlib.Path(__file__).absolute().parent.parent
    sys.path.append(str(path))
    main()
