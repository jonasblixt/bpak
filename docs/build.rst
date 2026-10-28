.. _Building and installing:

-----------------------
Building and installing
-----------------------

The library depends on mbedtls and liblzma

Build library and tool::

    $ cmake
    $ make
    $ sudo make install

The python package
------------------

Install the bpak python package from the repository root with pip, or add it
to a `uv <https://docs.astral.sh/uv>`_ project::

    $ pip install .
    $ uv add /path/to/bpak

The package is built with scikit-build-core and CMake and includes the
library, so it only needs the mbedtls and liblzma development packages and a C
compiler, for example ``libmbedtls-dev`` and ``liblzma-dev`` on Debian and
Ubuntu. CMake is installed from PyPI during the build when it is missing. The
package requires python 3.10 or later.

Build a source distribution and a wheel into ``dist/``::

    $ uv build

Running tests
-------------

Build and run the tests::

    $ cmake -B build -DBPAK_BUILD_TESTS=1
    $ cmake --build build
    $ ctest --test-dir build --output-on-failure

The tests have additional dependencies, see :ref:`Development setup`.


cmake configure options
-----------------------

===========================  ====================================================
Option                       Description
===========================  ====================================================
BPAK_BUILD_MINIMAL           Build a minimal version of the library
BPAK_BUILD_TESTS             Build the tests and the C extension of the python
                             package
BPAK_WERROR                  Treat compiler warnings as errors (default ON, OFF
                             when the python package is built)
===========================  ====================================================

The default setting is that everything is enabled except the tests.


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
