:mod:`bpak_bsdiff` --- bsdiff
=============================

.. module:: bsdiff
   :synopsis: BPAK bsdiff

The BPAK bsdiff module, bsdiff is used to generate a binary patch
between two different, binary, input files. This produces patches
without any compression, which is not meningful but BPAK provides this
API anyway to allow the user a choice of compression algorithm.

----------------------------------------------

Source code: :github-blob:`include/bpak/bsdiff.h`, :github-blob:`lib/bsdiff.c`

----------------------------------------------

.. doxygenfile:: include/bpak/bsdiff.h
   :project: bpak
