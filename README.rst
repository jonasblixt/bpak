.. image:: docs/bitpacker.svg
    :width: 10 %
.. image:: https://github.com/jonasblixt/bpak/actions/workflows/build.yml/badge.svg
    :target: https://github.com/jonasblixt/bpak/actions/workflows/build.yml
.. image:: https://scan.coverity.com/projects/20419/badge.svg
    :target: https://scan.coverity.com/projects/jonasblixt-bpak
.. image:: https://readthedocs.org/projects/bpak/badge/?version=latest
    :target: https://bpak.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

------------
Introduction
------------

Bitpacker or bpak for short is a tool and library for creating firmware archives
that can be cryptographically signed, support custom metadata and enable
advanced update schemes. Bitpacker is primarily designed for embedded systems.

Embedded systems are often composed of several software components, for example:
bootloader, kernel, file systems, device configuration, third party applications,
etc. It is common to have many different formats and tools for the various
components.

One of the main goals with bitpacker is to reduce the number of tools and
formats required to manage these components.

Documentation is available here: `BPAK documentation`_

-----------------------
Building and installing
-----------------------

The library depends on mbedtls and liblzma.

The bpak tool is part of the bpak python package, install it with
`uv <https://docs.astral.sh/uv>`_ or pip::

    $ uv tool install .
    $ pip install .

Set up a development environment with the tool and the test and lint tools::

    $ uv sync
    $ uv run bpak --help

Build and install the library::

    $ cmake -B build
    $ cmake --build build
    $ sudo cmake --install build

Running tests (requires cmocka, pytest and click)::

    $ cmake -B build -DBPAK_BUILD_TESTS=1
    $ cmake --build build && ctest --test-dir build --output-on-failure

.. _BPAK documentation: http://bpak.readthedocs.io/en/latest
