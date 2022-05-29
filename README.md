# CEMU #

[![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/cemu/blob/master/LICENSE) ![Python-Version](https://img.shields.io/pypi/pyversions/cemu.svg) [![PyPi-Version](https://img.shields.io/pypi/v/cemu.svg)](https://pypi.python.org/pypi/cemu) ![[Discord](https://discord.gg/qBn9MbG9vp)](https://img.shields.io/badge/Discord-CEmu-green)

![cemu-linux](https://i.imgur.com/iHtWvTL.png)


## Description ##


Writing assembly is fun. Assembly is the lowest language (humanly understandable) available to communicate with computers, and is crucial to understand the internal mechanisms of any machine. Unfortunately, setting up an environment to write, compile and run assembly for various architectures (x86, ARM, MIPS, SPARC) has always been painful. **CEmu** is an attempt to fix this by providing a bundled GUI application that empowers users to write assembly and test it by compiling it to bytecode and executing it in an QEMU-based emulator.

**CEmu** combines all the advantages of a basic assembly IDE, compilation and execution environment, by relying on the great libraries [Keystone](https://github.com/keystone-engine/keystone), [Unicorn](https://github.com/unicorn-engine/unicorn/) and [Capstone](https://github.com/aquynh/capstone) libraries in a Qt6 powered GUI.

It allows to test binary samples, check your shellcodes or even simply learn how to write assembly code, all of this for the following architectures:

  - x86-32 / x86-64
  - ARM / AArch64
  - MIPS / MIPS64
  - SPARC / SPARC64
  - PPC (but not emulation)

`CEmu` was mostly tested to work on Linux and Windows, but should work on MacOS.


## Installation ##

__Notes__

Since version 0.2.2, `cemu` is now Python3 only for simplicity and mostly also due to the fact that Python2 is not developed any longer. If your current installation of `cemu` is <= 0.2.1 and on Python2, please uninstall it and install it using Python3.

In addition, Python >= 3.10 is required, starting `0.6`.


### Quick install with PIP ###

Last stable from PyPI:

```bash
pip3 install cemu
```

Last stable from Github:

```bash
git clone https://github.com/hugsy/cemu
cd cemu
pip3 install --upgrade .
```

For 99% of cases, that's all you need to do. `cemu` will be installed in the associated `Scripts` directory:
 * On Linux by default the executable will be found as `/usr/local/bin/cemu` if installed as root, `~/.local/bin/cemu` for non-root
 * On Windows, `%PYTHON_DIR%\Scripts\cemu.exe` if installed with privileges, `%APPDATA%\Python\Python310\Scripts\cemu.exe` if not


## Contribution ##

`cemu` was created and maintained by myself, [`@_hugsy_`](https://twitter.com/_hugsy_), but kept fresh thanks to [all the contributors](https://github.com/hugsy/cemu/graphs/contributors).
