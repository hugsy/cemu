cemu
====

.. figure:: https://i.imgur.com/1vep3WM.png
   :alt: cemu-linux

   cemu-linux

Description
-----------

Writing assembly is fun. Assembly is the lowest language (humanly
understandable) available to communicate with computers, and is crucial
to understand the internal mechanisms of any machine. Unfortunately,
setting up an environment to write, compile and run assembly for various
architectures (x86, ARM, MIPS, SPARC) has always been painful. **CEmu**
is an attempt to fix this by providing a bundled GUI application that
empowers users to write assembly and test it by compiling it to bytecode
and executing it in an QEMU-based emulator.

**Cheap EMUlator** combines all the advantages of a basic assembly IDE,
compilation and execution environment, by relying on the great libraries
`Keystone <https://github.com/keystone-engine/keystone>`__,
`Unicorn <https://github.com/unicorn-engine/unicorn/>`__ and
`Capstone <https://github.com/aquynh/capstone>`__ engines in a Qt
powered GUI.

It allows to test binary samples, check your shellcodes or even simply
learn how to write assembly code, all of this for the following
architectures:

-  x86-32 / x86-64
-  Arm / AArch64
-  MIPS / MIPS64
-  SPARC / SPARC64
-  (more to come)

``CEmu`` was tested and works on Linux, Windows and MacOSX.

Installation
------------

Quick install with PIP
~~~~~~~~~~~~~~~~~~~~~~

**Notes**:

-  if you are using Kali Linux, there is a `known
   problem <https://github.com/keystone-engine/keystone/issues/235>`__
   with the installation of the ``keystone-engine`` package using PIP. A
   quick'n dirty fix for that would be (as ``root``):

.. code:: bash

    $ sudo updatedb
    $ sudo locate libkeystone.so
    $ sudo ln -sf /path/to/libkeystone.so/found/above /usr/local/lib/libkeystone.so

-  if you are using OSX, there is also a `known
   issue <https://github.com/aquynh/capstone/issues/74>`__ when
   installing ``capstone-engine`` from PIP, resulting in the ``.dylib``
   not being deployed at the right location. A quick fix for it is

.. code:: bash

    # locate the shared lib
    $ find ~  -type f -name libcapstone.dylib
    # link it in a valid correct library path
    $ ln -sf /path/to/libcapstone.dylib/found/above /usr/local/Cellar/python3/3.6.2/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages/capstone/libcapstone.dylib

From PyPI
^^^^^^^^^

This is the recommended way to install ``cemu`` as it will work out of
the box. You can install ``cemu`` on your system or using ``virtualenv``
or ``pipenv``, by running:

::

    pip3 install --user --upgrade cemu

From GitHub
^^^^^^^^^^^

::

    git clone https://github.com/hugsy/cemu && cd cemu
    pip3 install --user --upgrade .



Windows
^^^^^^^

The fastest way for Windows is to install the packaged binaries for: \*
Keystone (http://www.keystone-engine.org/download/) \* Capstone
(http://www.capstone-engine.org/download) \* Unicorn
(http://www.unicorn-engine.org/download/)

Then spawn ``cmd.exe`` and install the missing Python packages:
``python-qt5``, ``pygments``).

.. code:: bash

    C:>pip.exe install python-qt5 pygments

If you are running Python2, you will also need to install the package
``enum34``.

Contribution
------------

``cemu`` was created and maintained by myself,
```@_hugsy_`` <https://twitter.com/_hugsy_>`__, but kept fresh thanks to
`all the
contributors <https://github.com/hugsy/cemu/graphs/contributors>`__.
