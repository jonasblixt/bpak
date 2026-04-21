"""`bpak create` — create a new empty package."""

from __future__ import annotations

import os

import click

from .. import _bpak
from .._helpers import HASH_KIND_MAP, SIGN_KIND_MAP
from ._common import handle_bpak_errors


@click.command()
@click.argument("filename", type=click.Path())
@click.option(
    "--hash",
    "hash_kind",
    type=click.Choice(list(HASH_KIND_MAP.keys())),
    default="sha256",
    show_default=True,
    help="Hash algorithm",
)
@click.option(
    "--signature",
    "signature_kind",
    type=click.Choice(list(SIGN_KIND_MAP.keys())),
    default="prime256v1",
    show_default=True,
    help="Signature algorithm",
)
@click.option("--force", is_flag=True, help="Overwrite without asking")
@handle_bpak_errors
def create(filename: str, hash_kind: str, signature_kind: str, force: bool) -> None:
    """Create a new empty bpak file."""
    if os.path.exists(filename) and not force:
        if not click.confirm(f"File '{filename}' exists. Overwrite?"):
            return

    with _bpak.Package(filename, "wb") as pkg:
        pkg.hash_kind = HASH_KIND_MAP[hash_kind]
        pkg.signature_kind = SIGN_KIND_MAP[signature_kind]
