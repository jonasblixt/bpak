"""BPAK - Bit Packer.

Python interface to the bpak library, the C extension bpak._bpak. The
'bpak' command line tool is implemented in bpak.cli.

Errors of the library raise exceptions derived from Error, one per 'enum
bpak_errors' value. The error code is available as the class attribute
'code'.
"""

# The package exports all public names of the extension, its type stub
# _bpak.pyi lists them
from ._bpak import *  # noqa: F403
