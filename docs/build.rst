.. _Building and installing:

-----------------------
Building and installing
-----------------------

The library depends on mbedtls and liblzma.

Install Python module
---------------------

::

    $ pip install .

This compiles the library and Python extension from source. Requires
``libmbedtls-dev`` and ``liblzma-dev`` (or equivalent) installed on the
system.

Build C library and tool
------------------------

::

    $ mkdir build && cd build
    $ cmake ..
    $ make
    $ sudo make install

Running tests::

    $ mkdir build && cd build
    $ cmake .. -DBPAK_BUILD_TESTS=1
    $ make && make test


cmake configure options
-----------------------

===========================  ====================================================
Option                       Description
===========================  ====================================================
BPAK_BUILD_MINIMAL           Build a minimal version of the library
BPAK_BUILD_TOOL              Build the bpak command-line tool (default: ON)
BPAK_BUILD_TESTS             Build tests
===========================  ====================================================

The default setting builds the library and tool. Tests are disabled by default.


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
