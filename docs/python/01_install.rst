:mod:`Installation` --- Installing the BPAK python library
============================================================

.. module:: apython
   :synopsis: How to install the BPAK python library

See :ref:`Building and installing` section for details on installing bpak.

The following docker definition can be built from bpak root or by replacing
the COPY row with commands to clone the bpak repository.

.. literalinclude:: ../../examples/python/Dockerfile
  :language: docker

After building and installing you are able to import the bpak python module
to your python script::

  import bpak

