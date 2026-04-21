"""`bpak set` group — update metadata or header fields."""

from __future__ import annotations

import click

from bpak import _bpak
from bpak._helpers import encode_meta_value

from ._common import (
    BPAK_ID,
    at_least_one_of,
    handle_bpak_errors,
    open_package,
)


@click.group("set")
def set_() -> None:
    """Update a bpak file."""


@set_.command("meta")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.argument("value")
@click.option(
    "--encoder",
    type=click.Choice(["integer", "id"]),
    help="Interpret VALUE through this encoder before writing",
)
@click.option(
    "--part-ref",
    "part_ref",
    type=BPAK_ID,
    default=0,
    show_default=True,
    help="Pick the meta entry associated with this part",
)
@handle_bpak_errors
@open_package("r+")
def set_meta(
    pkg: _bpak.Package,
    id_: int,
    value: str,
    encoder: str | None,
    part_ref: int,
) -> None:
    """Update an existing metadata entry, or create it if absent."""
    new_data = encode_meta_value(value, encoder) if encoder else value.encode("ascii") + b"\x00"

    try:
        m = pkg.get_meta(id_, part_ref)
    except _bpak.Error:
        m = None

    if m is not None:
        if len(new_data) <= m.size:
            m.raw_data = new_data
        else:
            m.delete()
            pkg.add_meta(id_, part_ref, new_data)
    else:
        pkg.add_meta(id_, part_ref, new_data)


@set_.command("header")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--key-id",
    "key_id",
    type=BPAK_ID,
    help="Set the package's key_id header field",
)
@click.option(
    "--keystore-id",
    "keystore_id",
    type=BPAK_ID,
    help="Set the package's keystore_id header field",
)
@handle_bpak_errors
@open_package("r+")
def set_header(pkg: _bpak.Package, key_id: int | None, keystore_id: int | None) -> None:
    """Update header fields (key-id, keystore-id)."""
    at_least_one_of({"--key-id": key_id, "--keystore-id": keystore_id})
    if key_id is not None:
        pkg.key_id = key_id
    if keystore_id is not None:
        pkg.keystore_id = keystore_id
