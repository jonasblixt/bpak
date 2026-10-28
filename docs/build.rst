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

Running tests
-------------

The tests additionally depend on cmocka, pytest and openssl.

Build and run all tests::

    $ cmake -B build -DBPAK_BUILD_TESTS=1
    $ cmake --build build
    $ ctest --test-dir build --output-on-failure -j$(nproc)

The tests are split into three groups that can be selected with ``ctest -L``:

===========  ===================================================  ================
Label        Description                                          Location
===========  ===================================================  ================
unit         C unit tests of the library (cmocka)                 test/unit
cli          Tests of the bpak tool (pytest)                      test/cli
python       Tests of the python wrapper (pytest)                 test/python
===========  ===================================================  ================

The pytest based tests can also be run directly against a build directory,
which gives access to all pytest options::

    $ pytest test --bpak-build-dir build -k transport -v

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
