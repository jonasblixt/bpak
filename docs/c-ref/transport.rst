:mod:`bpak_transport` --- BPAK Transport API
=======================================

.. module:: transport
   :synopsis: BPAK transport API

The BPAK transport layer handles encoding and decoding of packages for transport.
This typically means that two versions of the same package is transport encoded
using the bsdiff algorithm.

----------------------------------------------

Source code: :github-blob:`include/bpak/transport.h`, :github-blob:`lib/transport_decode.c`, :github-blob:`lib/transport_encode.c`

----------------------------------------------

.. doxygenfile:: include/bpak/transport.h
   :project: bpak
