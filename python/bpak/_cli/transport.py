"""`bpak transport` group — transport metadata and encode/decode."""

from __future__ import annotations

import click

from .. import _bpak
from ._common import BPAK_ID, handle_bpak_errors, open_package


@click.group()
def transport() -> None:
    """Transport encoding/decoding operations."""


@transport.command("add")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.option(
    "--encoder",
    type=BPAK_ID,
    required=True,
    help="Transport encoder algorithm id (e.g. 'bsdiff' or '0x...')",
)
@click.option(
    "--decoder",
    type=BPAK_ID,
    required=True,
    help="Transport decoder algorithm id",
)
@handle_bpak_errors
@open_package("r+")
def transport_add(pkg, id_: int, encoder: int, decoder: int) -> None:
    """Add transport metadata linking a part to an encoder/decoder pair."""
    _bpak.add_transport_meta(pkg, id_, encoder, decoder)


def _run_codec(
    op,
    filename: str,
    output: str,
    origin: str | None,
) -> None:
    with _bpak.Package(filename, "rb") as pkg_in:
        with _bpak.Package(output, "wb") as pkg_out:
            if origin is not None:
                with _bpak.Package(origin, "rb") as pkg_origin:
                    op(pkg_in, pkg_out, pkg_origin)
            else:
                op(pkg_in, pkg_out)


@transport.command("encode")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=True,
    help="Path of the transport-encoded output package",
)
@click.option(
    "--origin",
    type=click.Path(exists=True, dir_okay=False),
    help="Origin package to diff against (for bsdiff-style encoders)",
)
@handle_bpak_errors
def transport_encode(filename: str, output: str, origin: str | None) -> None:
    """Transport-encode a package."""
    _run_codec(_bpak.transport_encode, filename, output, origin)


@transport.command("decode")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    required=True,
    help="Path of the transport-decoded output package",
)
@click.option(
    "--origin",
    type=click.Path(exists=True, dir_okay=False),
    help="Origin package used to reconstruct (for bsdiff-style decoders)",
)
@handle_bpak_errors
def transport_decode(filename: str, output: str, origin: str | None) -> None:
    """Transport-decode a package."""
    _run_codec(_bpak.transport_decode, filename, output, origin)
