"""`bpak delete` group — remove parts or metadata."""

from __future__ import annotations

import click

from ._common import (
    BPAK_ID,
    exactly_one_of,
    handle_bpak_errors,
    open_package,
)


@click.group()
def delete() -> None:
    """Delete parts or metadata from a bpak file."""


@delete.command("part")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="[ID]", type=BPAK_ID, required=False)
@click.option(
    "--all",
    "delete_all",
    is_flag=True,
    help="Delete every part in the package",
)
@click.option(
    "--keep-meta",
    is_flag=True,
    help="Keep metadata entries that reference the deleted parts",
)
@handle_bpak_errors
@open_package("r+")
def delete_part(
    pkg, id_: int | None, delete_all: bool, keep_meta: bool
) -> None:
    """Delete a single part, or --all of them."""
    choice = exactly_one_of(
        {"ID": id_ if id_ is not None else None, "--all": delete_all}
    )
    if choice == "--all":
        pkg.delete_all_parts(keep_meta=keep_meta)
    else:
        p = pkg.get_part(id_)
        p.delete(keep_meta=keep_meta)


@delete.command("meta")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
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
def delete_meta(pkg, id_: int, part_ref: int) -> None:
    """Delete a metadata entry."""
    m = pkg.get_meta(id_, part_ref)
    m.delete()
