#!/usr/bin/env python3

import argparse
import pathlib
import os

import cemu.const
import cemu.core
import cemu.log

THIS_FILE = pathlib.Path(__file__).absolute()


def setup_remote_debug(port: int = cemu.const.DEBUG_DEBUGPY_PORT):
    assert cemu.const.DEBUG
    import debugpy

    debugpy.listen(port)
    cemu.log.dbg("Waiting for debugger attach")
    debugpy.wait_for_client()
    cemu.log.dbg("Client connected, resuming session")


def main(argv: list[str]):
    parser = argparse.ArgumentParser(prog=cemu.const.PROGNAME, description=cemu.const.DESCRIPTION)
    parser.add_argument("filename")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args(argv)

    if bool(os.getenv("DEBUG", False)) or args.debug:
        cemu.const.DEBUG = True

    if cemu.const.DEBUG:
        cemu.log.register_sink(print)
        cemu.log.dbg("Starting in Debug Mode")
        if args.attach:
            setup_remote_debug()

    if args.cli:
        cemu.core.CemuCli(args)
    else:
        cemu.core.CemuGui()


def main_gui(debug: bool = False):
    args = [
        str(THIS_FILE),
    ]
    if debug:
        args.append("--debug")
    main(args)


def main_cli(debug: bool = False):
    args = [str(THIS_FILE), "--cli"]
    if debug:
        args.append("--debug")
    main(args)


if __name__ == "__main__":
    import sys

    path = THIS_FILE.parent.parent
    sys.path.append(str(path))
    main(sys.argv)
