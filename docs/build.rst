.. _Building and installing:

-----------------------
Building and installing
-----------------------

The library depends on mbedtls and liblzma

Build library and tool::

    $ cmake
    $ make
    $ sudo make install

Optionally build with python support::

    $ cmake -DBPAK_BUILD_PYTHON_WRAPPER=1

Running tests::

    $ cmake -DBPAK_BUILD_TESTS=1
    $ make && make test


cmake configure options
-----------------------

===========================  ====================================================
Option                       Description
===========================  ====================================================
BPAK_BUILD_MINIMAL           Build a minimal version of the library
BPAK_BUILD_PYTHON_WRAPPER    Build the python wrapper
BPAK_BUILD_TESTS             Build tests
===========================  ====================================================

The default setting is that everything is enabled except the python wrapper and
the tests.


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
