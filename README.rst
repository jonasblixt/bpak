.. image:: docs/bitpacker.svg
    :width: 10 %
.. image:: https://codecov.io/gh/jonasblixt/bpak/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/jonasblixt/bpak
.. image:: https://travis-ci.com/jonasblixt/bpak.svg?branch=master
    :target: https://travis-ci.com/jonasblixt/bpak
.. image:: https://scan.coverity.com/projects/20419/badge.svg
    :target: https://scan.coverity.com/projects/jonasblixt-bpak

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

The library has no external dependencies and the tool only depends on the c
library and the bpak library.

The 'autoconf-archive' package must be installed before running autoreconf.

Build library and tool::

    $ autoreconf -fi
    $ ./configure
    $ make
    $ sudo make install

Running tests::

    $ ./configure --enable-code-coverage
    $ make && make check

.. _BPAK documentation: http://bpak.readthedocs.io/en/latest
