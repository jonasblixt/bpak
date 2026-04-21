"""`bpak show` group — overview, meta, part, hash."""

from __future__ import annotations

import click

from bpak import _bpak

from ._common import (
    BPAK_ID,
    BPAK_METADATA_BYTES,
    bin2hex,
    binary_sink,
    flag_str,
    handle_bpak_errors,
    open_package,
)


class _ShowGroup(click.Group):
    """Dispatch ``bpak show FILE`` to the (hidden) summary subcommand.

    Allows the user to write ``bpak show FILE`` instead of the explicit
    ``bpak show summary FILE``.
    """

    def resolve_command(
        self,
        ctx: click.Context,
        args: list[str],
    ) -> tuple[str | None, click.Command | None, list[str]]:
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["summary", *args]
        return super().resolve_command(ctx, args)


@click.group(cls=_ShowGroup)
def show() -> None:
    """Show information about a bpak file."""


@show.command("summary", hidden=True)
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
@handle_bpak_errors
def show_summary(ctx: click.Context, filename: str) -> None:
    """Print a full overview of a bpak file."""
    verbose = (ctx.obj or {}).get("verbose", 0)
    with _bpak.Package(filename, "rb") as pkg:
        click.echo(f"BPAK File: {filename}")
        click.echo("")
        click.echo(f"Hash:        {_bpak.hash_kind_str(pkg.hash_kind)}")
        click.echo(f"Signature:   {_bpak.signature_kind_str(pkg.signature_kind)}")
        click.echo(f"Key ID:      {pkg.key_id:08x}")
        click.echo(f"Keystore ID: {pkg.keystore_id:08x}")

        click.echo("\nMetadata:")
        click.echo("    ID         Size   Meta ID              Part Ref   Data")
        for m in pkg.meta:
            s = _bpak.meta_to_string(pkg, m) or ""
            id_name = _bpak.id_to_string(m.id) or ""
            ref_str = f"{m.part_id_ref:08x}" if m.part_id_ref else "        "
            click.echo(f"    {m.id:08x}   {m.size:<3}    {id_name:<20s} {ref_str}   {s}")

        click.echo("\nParts:")
        click.echo("    ID         Size         Z-pad  Flags          Transport Size")
        for p in pkg.parts:
            flags = flag_str(p.flags)
            ts = p.transport_size if p.flags & _bpak.FLAG_TRANSPORT else p.size
            click.echo(f"    {p.id:08x}   {p.size:<12} {p.pad_bytes:<3}    {flags}       {ts:<12}")

        digest = pkg.digest
        if digest:
            click.echo(f"\nHeader hash: {bin2hex(digest)}")

        if verbose:
            meta_size = sum(m.size for m in pkg.meta)
            click.echo(f"Metadata usage: {meta_size}/{BPAK_METADATA_BYTES} bytes")
            click.echo(f"Transport size: {pkg.size} bytes")
            click.echo(f"Installed size: {pkg.installed_size} bytes")


@show.command("meta")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="[ID]", type=BPAK_ID, required=False)
@click.option(
    "--part-ref",
    "part_ref",
    type=BPAK_ID,
    default=None,
    help="Filter by part_id_ref; omit to list every ref. "
    "Use 0 to pick unassociated/global metadata entries.",
)
@handle_bpak_errors
@open_package("rb")
def show_meta(pkg: _bpak.Package, id_: int | None, part_ref: int | None) -> None:
    """Show one metadata entry, or list all of them."""
    found = False
    for m in pkg.meta:
        if id_ is not None and m.id != id_:
            continue
        if part_ref is not None and m.part_id_ref != part_ref:
            continue
        found = True
        s = _bpak.meta_to_string(pkg, m) or ""
        id_name = _bpak.id_to_string(m.id) or ""
        ref_str = f"{m.part_id_ref:08x}" if m.part_id_ref else "        "
        click.echo(f"{m.id:08x}  {id_name:<20s}  ref={ref_str}  size={m.size}  {s}")
    if id_ is not None and not found:
        if part_ref is not None:
            raise click.ClickException(
                f"no matching meta 0x{id_:08x} with part_ref 0x{part_ref:08x}"
            )
        raise click.ClickException(f"no matching meta 0x{id_:08x}")


@show.command("part")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.argument("id_", metavar="ID", type=BPAK_ID)
@click.option(
    "--hash",
    "show_part_hash",
    is_flag=True,
    help="Print the SHA-256 hash of the part instead of its summary",
)
@handle_bpak_errors
@open_package("rb")
def show_part(pkg: _bpak.Package, id_: int, show_part_hash: bool) -> None:
    """Show a single part."""
    if show_part_hash:
        click.echo(bin2hex(pkg.part_sha256(id_)))
        return
    p = pkg.get_part(id_)
    id_name = _bpak.id_to_string(p.id) or ""
    flags = flag_str(p.flags)
    ts = p.transport_size if p.flags & _bpak.FLAG_TRANSPORT else p.size
    click.echo(
        f"{p.id:08x}  {id_name:<20s}  size={p.size}  pad={p.pad_bytes}  "
        f"flags={flags}  transport_size={ts}"
    )


@show.command("hash")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--binary",
    "binary_mode",
    is_flag=True,
    help="Write the raw digest bytes to stdout",
)
@handle_bpak_errors
@open_package("rb")
def show_hash(pkg: _bpak.Package, binary_mode: bool) -> None:
    """Print the package header hash (Package.digest)."""
    digest = pkg.digest
    if not digest:
        raise click.ClickException("package has no digest")
    if binary_mode:
        sink = binary_sink(None)
        sink.write(digest)
        sink.flush()
    else:
        click.echo(bin2hex(digest))
