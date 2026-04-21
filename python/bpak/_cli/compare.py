"""`bpak compare` — diff two bpak files."""

from __future__ import annotations

import click

from .. import _bpak
from ._common import handle_bpak_errors


@click.command()
@click.argument("file1", type=click.Path(exists=True, dir_okay=False))
@click.argument("file2", type=click.Path(exists=True, dir_okay=False))
@handle_bpak_errors
def compare(file1: str, file2: str) -> None:
    """Compare two bpak files: metadata, part headers, and part contents."""
    with _bpak.Package(file1, "rb") as pkg1, _bpak.Package(file2, "rb") as pkg2:
        click.echo("Metadata:")
        meta1 = {(m.id, m.part_id_ref): m for m in pkg1.meta}
        meta2 = {(m.id, m.part_id_ref): m for m in pkg2.meta}
        for key in sorted(set(meta1) | set(meta2)):
            mid, mref = key
            m1 = meta1.get(key)
            m2 = meta2.get(key)
            id_name = _bpak.id_to_string(mid) or ""
            if m1 and m2:
                if m1.raw_data == m2.raw_data:
                    sym, color = "=", None
                else:
                    sym, color = "*", "yellow"
            elif m1:
                sym, color = "-", "red"
            else:
                sym, color = "+", "green"
            click.secho(
                f"  {sym} {mid:08x}  {id_name:<20s}  ref={mref:08x}",
                fg=color,
            )

        click.echo("\nParts:")
        parts1 = {p.id: p for p in pkg1.parts}
        parts2 = {p.id: p for p in pkg2.parts}
        for pid in sorted(set(parts1) | set(parts2)):
            p1 = parts1.get(pid)
            p2 = parts2.get(pid)
            id_name = _bpak.id_to_string(pid) or ""
            if p1 and p2:
                same = _parts_equal(pkg1, pkg2, p1, p2)
                sym, color = ("=", None) if same else ("*", "yellow")
            elif p1:
                sym, color = "-", "red"
            else:
                sym, color = "+", "green"
            size = (p1 or p2).size
            click.secho(
                f"  {sym} {pid:08x}  {id_name:<20s}  size={size}",
                fg=color,
            )


def _parts_equal(pkg1, pkg2, p1, p2) -> bool:
    """Compare part-header fields and content via SHA-256."""
    if (
        p1.size != p2.size
        or p1.pad_bytes != p2.pad_bytes
        or p1.flags != p2.flags
        or p1.transport_size != p2.transport_size
    ):
        return False
    try:
        return pkg1.part_sha256(p1.id) == pkg2.part_sha256(p2.id)
    except _bpak.Error:
        return False
