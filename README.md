# cemu

![cemu-linux](https://i.imgur.com/1vep3WM.png)

## Description


Writing assembly is fun. Assembly is the lowest language (humanly understandable) available to
communicate with computers, and is crucial to understand the internal mechanisms of any machine.
Unfortunately, setting up an environment to write, compile and run assembly for various architectures
(x86, ARM, MIPS, SPARC) has always been painful. **CEmu** is an attempt to fix this by providing a
bundled GUI application that empowers users to write assembly and test it by compiling it to bytecode
and executing it in an QEMU-based emulator.

**Cheap EMUlator** combines all the advantages of a basic assembly IDE, compilation and execution environment, by relying on the great libraries [Keystone](https://github.com/keystone-engine/keystone),
[Unicorn](https://github.com/unicorn-engine/unicorn/) and [Capstone](https://github.com/aquynh/capstone) engines in a Qt powered GUI.

It allows to test binary samples, check your shellcodes or even simply learn how to
write assembly code, all of this for the following architectures:

   - x86-32 / x86-64
   - Arm / AArch64
   - MIPS / MIPS64
   - SPARC / SPARC64
   - (more to come)

`CEmu` was tested and works on Linux, Windows and MacOSX.


## Pre-Requisites

  - `unicorn` and its Python bindings, as the emulation engine
  - `keystone` and its Python bindings, as the assembly engine
  - `capstone` and its Python bindings, as the disassembly engine
  - `PyQt5` for the GUI
  - `pygments` for the text colorization



## Requirements ##

### Quick install ###

On your system, or using `virtualenv` or `pipenv`:
```
pip3 install --user --upgrade .
```

### Linux / OSX ###

Use the script `requirements.sh` to install all the dependencies required for
`cemu`.

Since some packages can be installed via your package manager, the script may
ask for your root password if required.

```bash
$ ./requirements.sh
```

By default, the script will install the dependencies to have `cemu` running with
Python3. If you prefer to use Python2, simply add `--python2` to the command
line, like this:

```bash
$ ./requirements.sh --python2
```

### Windows

The fastest way for Windows is to install the packaged binaries for:
   * Keystone
     (http://www.keystone-engine.org/download/#python-module-for-windows-32---binaries-img-srcimagespythonpng-height28-width28-img-srcimageswindowspng-height28-width28)
   * Capstone
     (http://www.capstone-engine.org/download.html)
   * Unicorn
     (http://www.unicorn-engine.org/download/)

Then spawn `cmd.exe` and install the missing Python packages: `python-qt5`,
`pygments`).

```bash
C:>pip.exe install python-qt5 pygments
```

If you are running Python2, you will also need to install the
package `enum34`.

## OpenReil integration

[`OpenREIL`](https://github.com/Cr4sh/openreil) is an Open Source library
created by [@Cr4sh](https://twitter.com/@d_olex) that implements a translator
and tools for generating Intermediate Language level code (REIL). OpenREIL
library can be used optionally with `cemu`. The Current version of OpenREIL only
provides support for x86 (Intel) architecture.

If you use `cemu` with Python 2.7, you can also use
[`OpenReil`](https://github.com/Cr4sh/openreil) to generate IR
code based on the content of the `Code` panel.

![cemu-openreil](http://i.imgur.com/R1wXLpG.png)

To do so, follow the installation procedure for `OpenReil` by following the steps
[here](https://github.com/Cr4sh/openreil#_2).
