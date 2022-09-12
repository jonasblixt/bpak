------------
Architecture
------------

The bpak tool and library is organized in a few levels where the lower level
components are more freestanding than the higher level ones.

.. image:: architecture.svg

The core part of the library is ususally the only thing used on a constrained
embedded system that might provide, for example, crypto primitives through hardware.

The 'pkg' module ties all of the low level components together in the C library.

.. toctree::
   :maxdepth: 1
   :glob:
