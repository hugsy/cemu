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

Manual installation
~~~~~~~~~~~~~~~~~~~

If for some reason the installation via PIP fails, you can always run
``cemu`` by installing manually the following dependencies:

-  ``unicorn`` and its Python bindings, as the emulation engine
-  ``keystone`` and its Python bindings, as the assembly engine
-  ``capstone`` and its Python bindings, as the disassembly engine
-  ``PyQt5`` for the GUI
-  ``pygments`` for the text colorization

Linux / OSX
^^^^^^^^^^^

Use the script ``requirements.sh`` to install all the dependencies
required for ``cemu``.

Since some packages can be installed via your package manager, the
script may ask for your root password if required.

.. code:: bash

    $ ./requirements.sh

By default, the script will install the dependencies to have ``cemu``
running with Python3. If you prefer to use Python2, simply add
``--python2`` to the command line, like this:

.. code:: bash

    $ ./requirements.sh --python2

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

OpenReil integration
--------------------

```OpenREIL`` <https://github.com/Cr4sh/openreil>`__ is an Open Source
library created by [@Cr4sh](https://twitter.com/@d\_olex) that
implements a translator and tools for generating Intermediate Language
level code (REIL). OpenREIL library can be used optionally with
``cemu``. The Current version of OpenREIL only provides support for x86
(Intel) architecture.

If you use ``cemu`` with Python 2.7, you can also use
```OpenReil`` <https://github.com/Cr4sh/openreil>`__ to generate IR code
based on the content of the ``Code`` panel.

.. figure:: http://i.imgur.com/R1wXLpG.png
   :alt: cemu-openreil

   cemu-openreil

To do so, follow the installation procedure for ``OpenReil`` by
following the steps `here <https://github.com/Cr4sh/openreil#_2>`__.

Contribution
------------

``cemu`` was created and maintained by myself,
```@_hugsy_`` <https://twitter.com/_hugsy_>`__, but kept fresh thanks to
`all the
contributors <https://github.com/hugsy/cemu/graphs/contributors>`__.
