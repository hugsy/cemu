#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import sys
from cemu.core import Cemu


def check_dependencies():
    deps = ["PyQt5", "unicorn", "capstone", "keystone"]
    for d in deps:
        try:
            __import__(d)
        except ImportError:
            print("[-] Missing required dependency '%s'" % d)
            sys.exit(1)
    return


if __name__ == '__main__':
    check_dependencies()
    Cemu()
