.. image:: docs/bitpacker.svg
    :width: 10 %
.. image:: https://codecov.io/gh/jonasblixt/bpak/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/jonasblixt/bpak
.. image:: https://travis-ci.org/jonasblixt/bpak.svg?branch=master
    :target: https://travis-ci.org/jonasblixt/bpak
.. image:: https://scan.coverity.com/projects/20419/badge.svg
    :target: https://scan.coverity.com/projects/jonasblixt-bpak

------------
Introduction
------------

Bitpacker or bpak for short is a tool and library for creating firmware archives
that can be cryptographically signed, support custom metadata and enable
advanced update schemes.

Embedded systems are often composed of several software components, for example:
bootloader, kernel, filesystems, device configuration, third party applications,
etc. It is common to have many different formats and tools for the various
components.

One of the main goals with bitpacker is to reduce the number of tools and
formats required to manage these components.

-------------
Core concepts
-------------

Bitpacker supports two different signing schemes, one where the private key is
available on disk which is appropriate for un-controlled development keys but
makes life easier for day-to-day development. The second way is to export a
binary hash that can be signed in a controlled environment. Bitpacker supports
retrofitting DER formatted signatures, which, for example, is what openssl can
produce. This way an approved release candidate can be re-signed with
production keys without rebuilding.

The file format supports a transport mode. In this context transport means when
the data is being transfered to the device, for example during an update.
The transport mode

The bpak archives containes a fixed 4kByte header for metadata.
The metadata contains the physical layout of the archive and can contain custom
metadata, for example: version information, dependencies and custom data.

----------
Versioning
----------

Bitpacker uses semver 2.0.0
