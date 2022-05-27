#!/usr/bin/env python3

import pathlib
import sys


def main():
    from cemu.core import Cemu
    Cemu(sys.argv)


if __name__ == "__main__":
    path = pathlib.Path(__file__).absolute().parent.parent
    sys.path.append(str(path))
    main()
