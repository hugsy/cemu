#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import sys

def check_dependencies():
    deps = ["PyQt5", "unicorn", "capstone", "keystone", "pygments"]
    for d in deps:
        try:
            __import__(d)
        except ImportError:
            print("[-] Missing required dependency '%s'" % d)
            sys.exit(1)
    return


if __name__ == '__main__':
    from cemu.core import Cemu

    check_dependencies()
    Cemu()
