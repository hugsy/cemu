#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


def main() -> int:
    from cemu.core import Cemu
    Cemu(sys.argv)
    return 0


if __name__ == '__main__':
    sys.exit( main() )
