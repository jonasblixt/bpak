.. _Building and installing:

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


configure options
-----------------

===========================  ====================================================
Option                       Description
===========================  ====================================================
--disable-lzma               Disable support for lzma compression
--disable-tool               Disable the cli
--disable-bsdiff             Disable support for bspatch
--disable-bspatch            Disable support for bspatch
--disable-merkle             Disable the merkle tree generator
--disable-pkg-create         Disable support for creating packages
--disable-transport-encode   Disables the encoding portion of the transport layer
--disable-pkg-sign           Disable support for singing packages
===========================  ====================================================

The default setting is that everything is enabled


Build settings
--------------

========================  ===========
Parameter                 Description
========================  ===========
BPAK_CHUNK_BUFFER_LENGTH  Sets size of chunk buffers (Default: 4096b)
========================  ===========

.. toctree::
   :maxdepth: 1
   :glob:

   build/*
