# cemu

## Description

Cheap EMUlator is a simple tool to combine together all the features of [Keystone](https://github.com/keystone-engine/keystone),
[Unicorn](https://github.com/unicorn-engine/unicorn/) and [Capstone](https://github.com/aquynh/capstone) engines in a Qt powered GUI.

It allows to test binary samples, check your shellcodes or even simply learn how to
write assembly code, all of this for the following architectures:

   - x86-32 / x86-64
   - Arm / AArch64
   - MIPS / MIPS64
   - SPARC / SPARC64
   - (more to come)


## Pre-Requisites

  - `unicorn` and its Python bindings, as the emulation engine
  - `keystone` and its Python bindings, as the assembly engine
  - `capstone` and its Python bindings, as the disassembly engine
  - `PyQt5` for the GUI
  - `pygments` for the text colorization


## Show Me ##

### Linux ###

![cemu-linux](https://i.imgur.com/1vep3WM.png)

### Windows ###

![cemu-win](http://i.imgur.com/rn183yR.png)

### OSX ###

![cemu-osx](https://i.imgur.com/8tGqwE7.png)


## Requirements ##

### Linux ###

Use your distribution package manager to ensure that you have:

  * `cmake`
  * Python3 (prefered, but Python 2 works as well) + `pip3`
  * a C compiler (gcc, clang, etc.)

Then run the install script `./requirements.sh`.


### OSX ###

Use `brew` to install:

  * `cmake`
  * Python3 (`pip3` will be automatically installed)
  * `pkg-config`
  * `glib`

Finally you can execute the script `./requirements.sh` that will install the
rest of the requirements to run `cemu`.


### Windows

The fastest way for Windows is to install the packaged binaries for:
   * Keystone
     (http://www.keystone-engine.org/download/#python-module-for-windows-32---binaries-img-srcimagespythonpng-height28-width28-img-srcimageswindowspng-height28-width28)
   * Capstone
     (http://www.capstone-engine.org/download.html)
   * Unicorn
     (http://www.unicorn-engine.org/download/)

Then spawn `cmd.exe` and install the missing Python packages: `python-qt5`,
`pygments`). If you are running Python2, you will also need to install the
package `enum34`.
