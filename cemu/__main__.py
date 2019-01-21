#!/usr/bin/env python3
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

def run():
    from cemu.core import Cemu
    Cemu()
    return

def main():
    check_dependencies()
    run()
    return

if __name__ == '__main__':
    main()
    sys.exit(0)
