.. image:: docs/bitpacker.svg
    :width: 10 %
.. image:: https://codecov.io/gh/jonasblixt/bpak/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/jonasblixt/bpak
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

The library depends to mbedtls, liblzma, uuid

Build library and tool::

    $ mkdir build && cd build
    $ cmake ..
    $ make
    $ sudo make install

Running tests::

    $ cmake .. -DBPAK_BUILD_TESTS=1
    $ make && make test

.. _BPAK documentation: http://bpak.readthedocs.io/en/latest
