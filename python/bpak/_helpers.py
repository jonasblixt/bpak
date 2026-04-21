"""Helper utilities for the bpak CLI."""

from __future__ import annotations

import struct
import uuid

from . import (
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    SIGN_PRIME256v1,
    SIGN_RSA4096,
    SIGN_SECP384r1,
    SIGN_SECP521r1,
    id as bpak_id,
)

HASH_KIND_MAP: dict[str, int] = {
    "sha256": HASH_SHA256,
    "sha384": HASH_SHA384,
    "sha512": HASH_SHA512,
}

SIGN_KIND_MAP: dict[str, int] = {
    "prime256v1": SIGN_PRIME256v1,
    "secp384r1": SIGN_SECP384r1,
    "secp521r1": SIGN_SECP521r1,
    "rsa4096": SIGN_RSA4096,
}


def resolve_id(arg: str) -> int:
    """Convert a name string or numeric literal to a bpak_id_t.

    Accepts:
      - ``0x...`` / ``0X...`` hex literals (any width).
      - Bare decimal literals (``0``, ``42``, ...). Note: this means a
        part or metadata named exactly ``"123"`` must be written as
        ``0x...`` to disambiguate from the decimal 123.
      - Any other string, which is CRC32-hashed via ``bpak_id()``.
    """
    if arg.startswith(("0x", "0X")):
        return int(arg, 16)
    if arg.isdigit():
        return int(arg)
    return bpak_id(arg)


def encode_meta_value(value: str, encoder: str) -> bytes:
    """Encode a metadata value using the specified encoder."""
    if encoder == "integer":
        return struct.pack("<Q", int(value, 0))
    elif encoder == "id":
        return struct.pack("<I", bpak_id(value))
    elif encoder == "uuid":
        return uuid.UUID(value).bytes
    else:
        msg = f"unknown encoder: {encoder}"
        raise ValueError(msg)
