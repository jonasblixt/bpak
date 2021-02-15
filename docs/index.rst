Welcome to the bpak documentation
=================================

Bitpacker or bpak for short is a tool and library for creating firmware archives
that can be cryptographically signed, support custom metadata and enable
advanced update schemes. Bitpacker is primarily designed for embedded systems.

Embedded systems are often composed of several software components, for example:
bootloader, kernel, file systems, device configuration, third party applications,
etc. It is common to have many different formats and tools for the various
components.

One of the main goals with bitpacker is to reduce the number of tools and
formats required to manage these components.

.. toctree::
   :maxdepth: 1
   :titlesonly:
   :hidden:

   intro
   build
   architecture
   user-guide
   developer-guide
   c-library-reference
   python-library-reference
   python-examples
   license

