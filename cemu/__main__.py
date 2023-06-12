#!/usr/bin/env python3

import pathlib
import sys

import cemu.core


def main():
    if "--cli" in sys.argv:
        cemu.core.CemuCli(sys.argv)
        return

    cemu.core.CemuGui(sys.argv)
    return


if __name__ == "__main__":
    path = pathlib.Path(__file__).absolute().parent.parent
    sys.path.append(str(path))
    main()
