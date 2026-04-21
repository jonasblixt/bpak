"""`bpak extract` group — write parts or metadata out of a package."""

from __future__ import annotations

import click

from ._common import (
    BPAK_ID,
    binary_sink,
    handle_bpak_errors,
    open_package,
)


@click.group()
def extract() -> None:
    """Extract parts or metadata from a bpak file."""


@extract.command("part")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    help="Write to PATH; default is stdout (refused when stdout is a TTY)",
)
@handle_bpak_errors
@open_package("rb")
def extract_part(pkg, id_: int, output: str | None) -> None:
    """Extract a part."""
    if output is not None:
        pkg.extract_file(id_, output)
        return
    p = pkg.get_part(id_)
    sink = binary_sink(None)
    sink.write(p.read_data())
    sink.flush()


@extract.command("meta")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    help="Write to PATH; default is stdout (refused when stdout is a TTY)",
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
@open_package("rb")
def extract_meta(
    pkg, id_: int, output: str | None, part_ref: int
) -> None:
    """Extract a metadata value."""
    m = pkg.get_meta(id_, part_ref)
    data = m.raw_data
    if output is not None:
        with open(output, "wb") as f:
            f.write(data)
    else:
        sink = binary_sink(None)
        sink.write(data)
        sink.flush()
