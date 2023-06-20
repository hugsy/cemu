#!/usr/bin/env python3

import pathlib
import sys

import cemu.const
import cemu.core
import cemu.log


def main():
    if cemu.const.DEBUG:
        cemu.log.register_sink(print)
        cemu.log.dbg("Starting in Debug Mode")

    if len(sys.argv) >= 2 and sys.argv[1] == "cli":
        cemu.core.CemuCli(sys.argv[2:])
        return

    cemu.core.CemuGui(sys.argv)
    return


if __name__ == "__main__":
    path = pathlib.Path(__file__).absolute().parent.parent
    sys.path.append(str(path))
    main()
