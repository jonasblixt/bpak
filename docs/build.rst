-----------------------
Building and installing
-----------------------

The library has no external dependencies and the tool only depends on the c
library and the bpak library.

The 'autoconf-archive' package must be installed before running autoreconf.

Build library and tool::

    $ autoreconf -fi
    $ ./configure
    $ make
    $ sudo make install

Optionally build with python support::

    $ ./configure --enable-python-library

Running tests::

    $ ./configure --enable-code-coverage
    $ make && make check

.. toctree::
   :maxdepth: 1
   :glob:

   build/*
