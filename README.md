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
