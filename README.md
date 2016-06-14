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


## Show Me

![demo](https://i.imgur.com/7CZbuHO.png)

## Requirements

### Automatically

Run the install script `./requirements.sh`.

### Manually
```bash
# keystone
$ git clone https://github.com/keystone-engine/keystone.git
$ mkdir -p keystone/build && cd keystone/build
$ cmake .. && make -j8
$ sudo make install
$ cd ../bindings/python && sudo make install # or sudo make install3 for Python3

# capstone
$ git clone https://github.com/aquynh/capstone.git
$ mkdir -p capstone/build && cd capstone/build
$ cmake .. && make -j8
$ sudo make install
$ cd ../bindings/python && sudo make install # or sudo make install3 for Python3

# unicorn
$ git clone https://github.com/unicorn-engine/unicorn.git
$ cd unicorn
$ ./make.sh -j8
$ sudo ./make.sh install
$ cd ./bindings/python && sudo make install # or sudo make install3 for Python3
```
