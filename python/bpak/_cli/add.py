"""`bpak add` group — add part, meta, key, merkle to a package."""

from __future__ import annotations

from pathlib import Path

import click

from bpak import _bpak
from bpak._helpers import encode_meta_value

from ._common import (
    BPAK_ID,
    BPAK_METADATA_BYTES,
    exactly_one_of,
    handle_bpak_errors,
    open_package,
)


@click.group()
def add() -> None:
    """Add content to a bpak file."""


@add.command("part")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID")
@click.option(
    "--from",
    "from_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the source file whose bytes become the part contents",
)
@click.option(
    "--no-hash",
    is_flag=True,
    help="Exclude this part from the package hash",
)
@handle_bpak_errors
@open_package("r+")
def add_part(pkg: _bpak.Package, id_: str, from_path: str, no_hash: bool) -> None:
    """Add a raw part from a file.

    The ID is the part's symbolic name (e.g. "rootfs"); the underlying
    library hashes it into a 32-bit ID.
    """
    flags = _bpak.FLAG_EXCLUDE_FROM_HASH if no_hash else 0
    pkg.add_file(id_, from_path, flags=flags)


@add.command("meta")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.option(
    "--from-string",
    "from_string",
    help="Value as a string (null-terminated by default, or passed through an encoder)",
)
@click.option(
    "--from-file",
    "from_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Read the raw metadata bytes from this file",
)
@click.option(
    "--encoder",
    type=click.Choice(["uuid", "integer", "id"]),
    help="Interpret --from-string as this type before storing",
)
@click.option(
    "--part-ref",
    "part_ref",
    type=BPAK_ID,
    default=0,
    show_default=True,
    help="Associate this metadata with the given part",
)
@handle_bpak_errors
@open_package("r+")
def add_meta(
    pkg: _bpak.Package,
    id_: int,
    from_string: str | None,
    from_file: str | None,
    encoder: str | None,
    part_ref: int,
) -> None:
    """Add a metadata entry."""
    exactly_one_of({"--from-string": from_string, "--from-file": from_file})

    if encoder and from_file:
        raise click.UsageError("--encoder only applies with --from-string")

    if from_string is not None:
        if encoder:
            data = encode_meta_value(from_string, encoder)
        else:
            data = from_string.encode("ascii") + b"\x00"
    else:
        assert from_file is not None
        data = Path(from_file).read_bytes()

    if len(data) > BPAK_METADATA_BYTES:
        raise click.ClickException(
            f"metadata value too large ({len(data)} > {BPAK_METADATA_BYTES} bytes)"
        )

    pkg.add_meta(id_, part_ref, data)


@add.command("key")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID")
@click.option(
    "--from",
    "from_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the public key file to embed",
)
@handle_bpak_errors
@open_package("r+")
def add_key(pkg: _bpak.Package, id_: str, from_path: str) -> None:
    """Embed a public key as a part (ID is the key's symbolic name)."""
    pkg.add_key(id_, from_path)


@add.command("merkle")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID")
@click.option(
    "--from",
    "from_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Source file to hash into a merkle tree part",
)
@handle_bpak_errors
@open_package("r+")
def add_merkle(pkg: _bpak.Package, id_: str, from_path: str) -> None:
    """Add a part with an accompanying merkle tree (ID is the part's symbolic name)."""
    pkg.add_file(id_, from_path, with_merkle_tree=True)
