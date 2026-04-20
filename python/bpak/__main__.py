"""BPAK CLI - Bit Packer command line tool."""

from __future__ import annotations

import functools
import os
import struct
import sys
from pathlib import Path

import click

from . import _bpak
from ._helpers import HASH_KIND_MAP, SIGN_KIND_MAP, encode_meta_value, resolve_id

_verbose_level = 0


def _log_callback(level: int, msg: str) -> None:
    if level == 0:
        click.echo(msg, nl=False, err=True)
    elif level <= _verbose_level:
        click.echo(msg, nl=False)


def _apply_verbose(level: int) -> None:
    """Install or clear the bpak log callback for this command.

    Cleared on level==0 because _bpak stores the callback in a static
    module-global; without clearing, a verbose call would leak logging
    into later non-verbose calls in the same process.
    """
    global _verbose_level
    _verbose_level = level
    if level > 0:
        _bpak.set_log_func(_log_callback)
    else:
        _bpak.set_log_func(None)


def _print_version(
    _ctx: click.Context, _param: click.Option, value: bool
) -> None:
    if value:
        try:
            from importlib.metadata import version

            click.echo(f"BitPacker {version('bpak')}")
        except Exception:
            click.echo("BitPacker (unknown version)")
        sys.exit(0)


def _handle_error(func):
    """Decorator that catches bpak errors and converts to ClickException."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except _bpak.Error as e:
            raise click.ClickException(str(e)) from e

    return wrapper


def _verbose_option(f):
    return click.option("-v", "--verbose", count=True, help="Verbose output")(f)


@click.group()
@click.option(
    "-V",
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_print_version,
    help="Display version and exit",
)
def cli() -> None:
    """BPAK - Bit Packer."""


# --- create ---


@cli.command()
@click.argument("filename", type=click.Path())
@click.option(
    "-H",
    "--hash-kind",
    type=click.Choice(list(HASH_KIND_MAP.keys())),
    default="sha256",
    help="Hash algorithm",
)
@click.option(
    "-S",
    "--signature-kind",
    type=click.Choice(list(SIGN_KIND_MAP.keys())),
    default="prime256v1",
    help="Signature algorithm",
)
@click.option("-Y", "--force", is_flag=True, help="Overwrite without asking")
@_verbose_option
@_handle_error
def create(
    filename: str,
    hash_kind: str,
    signature_kind: str,
    force: bool,
    verbose: int,
) -> None:
    """Create an empty bpak file."""
    _apply_verbose(verbose)
    if os.path.exists(filename) and not force:
        if not click.confirm(f"File '{filename}' exists. Overwrite?"):
            return

    with _bpak.Package(filename, "wb") as pkg:
        pkg.hash_kind = HASH_KIND_MAP[hash_kind]
        pkg.signature_kind = SIGN_KIND_MAP[signature_kind]


# --- add ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-p", "--part", "part_name", help="Add part with given name")
@click.option("-m", "--meta", "meta_name", help="Add metadata with given name")
@click.option(
    "-f", "--from-file", type=click.Path(exists=True), help="Load data from file"
)
@click.option("-s", "--from-string", help="Load data from string")
@click.option(
    "-e",
    "--encoder",
    type=click.Choice(["uuid", "integer", "id", "key", "merkle"]),
    help="Encoder for data",
)
@click.option(
    "-F",
    "--set-flag",
    type=click.Choice(["dont-hash"]),
    help="Set flag on part",
)
@click.option("-r", "--part-ref", help="Reference part")
@_verbose_option
@_handle_error
def add(
    filename: str,
    part_name: str | None,
    meta_name: str | None,
    from_file: str | None,
    from_string: str | None,
    encoder: str | None,
    set_flag: str | None,
    part_ref: str | None,
    verbose: int,
) -> None:
    """Add parts or metadata to a bpak file."""
    _apply_verbose(verbose)
    if not part_name and not meta_name:
        raise click.UsageError("Must specify --part or --meta")

    with _bpak.Package(filename, "r+") as pkg:
        if meta_name:
            meta_id = resolve_id(meta_name)
            ref_id = resolve_id(part_ref) if part_ref else 0

            if encoder and from_string:
                data = encode_meta_value(from_string, encoder)
            elif from_string:
                data = from_string.encode("ascii") + b"\x00"
            elif from_file:
                data = Path(from_file).read_bytes()
            else:
                raise click.UsageError(
                    "Must specify --from-string or --from-file for metadata"
                )

            if len(data) > _bpak.BPAK_METADATA_BYTES if hasattr(_bpak, 'BPAK_METADATA_BYTES') else len(data) > 1920:
                raise click.ClickException("Metadata too large")

            pkg.add_meta(meta_id, ref_id, data)

        elif part_name:
            flags = 0
            if set_flag == "dont-hash":
                flags = _bpak.FLAG_EXCLUDE_FROM_HASH

            if encoder == "key":
                if not from_file:
                    raise click.UsageError("--encoder key requires --from-file")
                pkg.add_key(part_name, from_file, flags=flags)
            elif encoder == "merkle":
                if not from_file:
                    raise click.UsageError(
                        "--encoder merkle requires --from-file"
                    )
                pkg.add_file(
                    part_name, from_file, with_merkle_tree=True, flags=flags
                )
            else:
                if not from_file:
                    raise click.UsageError("--from-file required for parts")
                pkg.add_file(part_name, from_file, flags=flags)


# --- show ---


def _flag_str(flags: int) -> str:
    chars = list("--------")
    if flags & _bpak.FLAG_EXCLUDE_FROM_HASH:
        chars[0] = "h"
    if flags & _bpak.FLAG_TRANSPORT:
        chars[1] = "T"
    return "".join(chars)


def _bin2hex(data: bytes) -> str:
    return "".join(f"{b:02x}" for b in data)


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-m", "--meta", "meta_name", help="Show specific metadata")
@click.option("-p", "--part", "part_name", help="Show specific part")
@click.option("-P", "--part-hash", help="Show SHA256 hash of a part")
@click.option("-H", "--hash", "show_hash", is_flag=True, help="Show package hash")
@click.option(
    "-B", "--binary-hash", is_flag=True, help="Output hash in binary form"
)
@_verbose_option
@_handle_error
def show(
    filename: str,
    meta_name: str | None,
    part_name: str | None,
    part_hash: str | None,
    show_hash: bool,
    binary_hash: bool,
    verbose: int,
) -> None:
    """Show information about a bpak file."""
    _apply_verbose(verbose)

    with _bpak.Package(filename, "r+") as pkg:
        h_kind = pkg.hash_kind
        s_kind = pkg.signature_kind

        if meta_name:
            meta_id = resolve_id(meta_name)
            # In C show.c:126-128, when -m is given, -p reinterprets as
            # the part_id_ref filter on the metadata lookup.
            ref_id = resolve_id(part_name) if part_name else None

            for m in pkg.meta:
                if m.id == meta_id:
                    if ref_id is not None and m.part_id_ref != ref_id:
                        continue
                    s = _bpak.meta_to_string(pkg, m)
                    if s:
                        click.echo(s)
                    return
            raise click.ClickException(f"Could not find meta '{meta_name}'")

        if part_name:
            part_id = resolve_id(part_name)
            for p in pkg.parts:
                if p.id == part_id:
                    click.echo(f"Found 0x{p.id:x}, {p.size} bytes")
                    return
            raise click.ClickException(f"Could not find part '{part_name}'")

        if part_hash:
            part_hash_id = resolve_id(part_hash)
            h = pkg.part_sha256(part_hash_id)
            click.echo(_bin2hex(h))
            return

        if binary_hash:
            digest = pkg.digest
            if digest:
                sys.stdout.buffer.write(digest)
            return

        if show_hash:
            digest = pkg.digest
            if digest:
                click.echo(_bin2hex(digest))
            return

        # Full display
        click.echo(f"BPAK File: {filename}")
        click.echo("")
        click.echo(f"Hash:        {_bpak.hash_kind_str(h_kind)}")
        click.echo(f"Signature:   {_bpak.signature_kind_str(s_kind)}")
        click.echo(f"Key ID:      {pkg.key_id:08x}")
        click.echo(f"Keystore ID: {pkg.keystore_id:08x}")

        click.echo("\nMetadata:")
        click.echo("    ID         Size   Meta ID              Part Ref   Data")

        for m in pkg.meta:
            s = _bpak.meta_to_string(pkg, m)
            if s is None:
                s = ""
            id_name = _bpak.id_to_string(m.id)
            if id_name is None:
                id_name = ""
            ref_str = f"{m.part_id_ref:08x}" if m.part_id_ref else "        "
            click.echo(
                f"    {m.id:08x}   {m.size:<3}    {id_name:<20s} {ref_str}   {s}"
            )

        click.echo("\nParts:")
        click.echo(
            "    ID         Size         Z-pad  Flags          Transport Size"
        )

        for p in pkg.parts:
            flags = _flag_str(p.flags)
            ts = p.transport_size if p.flags & _bpak.FLAG_TRANSPORT else p.size
            click.echo(
                f"    {p.id:08x}   {p.size:<12} {p.pad_bytes:<3}    {flags}"
                f"       {ts:<12}"
            )

        # Hashes
        digest = pkg.digest
        if digest:
            click.echo(f"\nHeader hash:  {_bin2hex(digest)}")
            payload_digest = pkg.digest
            if payload_digest:
                click.echo(f"Payload hash: {_bin2hex(payload_digest)}")

        if verbose:
            meta_size = sum(m.size for m in pkg.meta)
            click.echo(f"Metadata usage: {meta_size}/1920 bytes")
            click.echo(f"Transport size: {pkg.size} bytes")
            click.echo(f"Installed size: {pkg.installed_size} bytes")


# --- sign ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-k", "--key", type=click.Path(exists=True), help="Sign using key")
@click.option(
    "-f",
    "--signature",
    type=click.Path(exists=True),
    help="Write pre-computed signature from file",
)
@_verbose_option
@_handle_error
def sign(
    filename: str, key: str | None, signature: str | None, verbose: int
) -> None:
    """Sign a bpak file."""
    _apply_verbose(verbose)
    if not key and not signature:
        raise click.UsageError("Must specify --key or --signature")

    with _bpak.Package(filename, "r+") as pkg:
        if signature:
            sig_data = Path(signature).read_bytes()
            if len(sig_data) > 512:
                raise click.ClickException(
                    f"Signature file too large ({len(sig_data)} > 512 bytes)"
                )
            pkg.signature = sig_data
        elif key:
            pkg.sign(key)


# --- verify ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option(
    "-k", "--key", type=click.Path(exists=True), help="Verify using public key"
)
@click.option(
    "-K",
    "--keystore",
    type=click.Path(exists=True),
    help="Verify using keystore bpak file",
)
@_verbose_option
@_handle_error
def verify(
    filename: str, key: str | None, keystore: str | None, verbose: int
) -> None:
    """Verify a bpak file signature."""
    _apply_verbose(verbose)
    if not key and not keystore:
        raise click.UsageError("Must specify --key or --keystore")

    with _bpak.Package(filename, "r+") as pkg:
        if keystore:
            pkg.verify_with_keystore(keystore)
        elif key:
            pkg.verify(key)

    click.echo("Verification OK")


# --- generate ---


@cli.command()
@click.argument("generator")
@click.argument("rest", nargs=-1)
@click.option("-n", "--name", help="Name for generated keystore")
@click.option("-d", "--decorate", is_flag=True, help="Add section attributes")
@_verbose_option
@_handle_error
def generate(
    generator: str,
    rest: tuple[str, ...],
    name: str | None,
    decorate: bool,
    verbose: int,
) -> None:
    """Generate code or translations.

    Generators:
      id <string>             Translate string to bpak id
      keystore <file> -n NAME Generate C keystore from bpak file
    """
    _apply_verbose(verbose)

    if generator == "id":
        if len(rest) != 1:
            raise click.UsageError("generate id requires one positional argument")
        id_string = rest[0]
        click.echo(f'id("{id_string}") = 0x{_bpak.id(id_string):08x}')
        return

    if generator == "keystore":
        if len(rest) != 1:
            raise click.UsageError("generate keystore requires a filename")
        filename = rest[0]
        if not os.path.exists(filename):
            raise click.UsageError(f"File not found: {filename}")
        if not name:
            raise click.UsageError("generate keystore requires --name")

        from importlib.metadata import version as pkg_version

        try:
            ver = pkg_version("bpak")
        except Exception:
            ver = "unknown"

        key_kind_names = {
            _bpak.KEY_PUB_PRIME256v1: "BPAK_KEY_PUB_PRIME256v1",
            _bpak.KEY_PUB_SECP384r1: "BPAK_KEY_PUB_SECP384r1",
            _bpak.KEY_PUB_SECP521r1: "BPAK_KEY_PUB_SECP521r1",
            _bpak.KEY_PUB_RSA4096: "BPAK_KEY_PUB_RSA4096",
        }

        with _bpak.Package(filename, "rb") as pkg:
            ks_meta = pkg.get_meta(_bpak.id("keystore-provider-id"))
            ks_provider_id = struct.unpack("<I", ks_meta.raw_data[:4])[0]

            safe_name = name.replace("-", "_")

            print(f"/* Automatically generated with bpak {ver} */")
            print("#include <bpak/bpak.h>")
            print("#include <bpak/keystore.h>")
            print("\n")

            key_decorator = '__attribute__((section (".keystore_key"))) '
            header_decorator = '__attribute__((section (".keystore_header"))) '

            key_index = 0
            for p in pkg.parts:
                data = p.read_data()

                kind, key_data = _bpak.parse_public_key(data)

                if kind not in key_kind_names:
                    raise click.ClickException(
                        f"Unsupported key type ({kind}) for part 0x{p.id:x}"
                    )

                print(
                    f"const struct bpak_key keystore_{safe_name}_key{key_index} "
                    f"{key_decorator if decorate else ''}="
                )
                print("{")
                print(f"    .id = 0x{p.id:x},")
                print(f"    .size = {len(key_data)},")
                print(f"    .kind = {key_kind_names[kind]},")
                print("    .data =")
                print("    {")
                line = "            "
                for i, b in enumerate(key_data):
                    line += f"0x{b:02x}, "
                    if (i + 1) % 8 == 0:
                        print(line)
                        line = "            "
                if line.strip():
                    print(line)
                print("    },")
                print("};\n")
                key_index += 1

            print(
                f"const struct bpak_keystore keystore_{safe_name} "
                f"{header_decorator if decorate else ''}="
            )
            print("{")
            print(f"    .id = 0x{ks_provider_id:x},")
            print(f"    .no_of_keys = {key_index},")
            print("    .verified = true,")
            print("    .keys =")
            print("    {")
            for i in range(key_index):
                print(
                    f"        (struct bpak_key *) &keystore_{safe_name}_key{i},"
                )
            print("    },")
            print("};")
        return

    raise click.UsageError(f"Unknown generator: {generator}")


# --- transport ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-a", "--add", "add_mode", is_flag=True, help="Add transport meta")
@click.option(
    "-E", "--encode", "encode_mode", is_flag=True, help="Encode for transport"
)
@click.option("-D", "--decode", "decode_mode", is_flag=True, help="Decode package")
@click.option(
    "-r",
    "--part-ref",
    "--part",
    "part_ref",
    help="Part to add transport meta for (alias --part)",
)
@click.option("-e", "--encoder", help="Encoder algorithm name")
@click.option("-d", "--decoder", help="Decoder algorithm name")
@click.option("-o", "--output", type=click.Path(), help="Output file")
@click.option(
    "-O", "--origin", type=click.Path(exists=True), help="Origin data file"
)
@_verbose_option
@_handle_error
def transport(
    filename: str,
    add_mode: bool,
    encode_mode: bool,
    decode_mode: bool,
    part_ref: str | None,
    encoder: str | None,
    decoder: str | None,
    output: str | None,
    origin: str | None,
    verbose: int,
) -> None:
    """Transport encoding/decoding operations."""
    _apply_verbose(verbose)

    mode_count = sum([add_mode, encode_mode, decode_mode])
    if mode_count == 0:
        raise click.UsageError("One of --add, --encode or --decode is required")
    if mode_count > 1:
        raise click.UsageError(
            "Only one of --add, --encode or --decode is allowed"
        )

    if add_mode:
        if not encoder or not decoder:
            raise click.UsageError(
                "--add requires --encoder and --decoder"
            )
        with _bpak.Package(filename, "r+") as pkg:
            ref_id = resolve_id(part_ref) if part_ref else 0
            encoder_id = resolve_id(encoder)
            decoder_id = resolve_id(decoder)
            _bpak.add_transport_meta(pkg, ref_id, encoder_id, decoder_id)
        return

    # encode / decode share output requirement
    if not output:
        raise click.UsageError("--encode/--decode requires --output")

    op = _bpak.transport_encode if encode_mode else _bpak.transport_decode

    with _bpak.Package(filename, "rb") as pkg_in:
        with _bpak.Package(output, "wb") as pkg_out:
            if origin:
                with _bpak.Package(origin, "rb") as pkg_origin:
                    op(pkg_in, pkg_out, pkg_origin)
            else:
                op(pkg_in, pkg_out)


# --- set ---


@cli.command("set")
@click.argument("filename", type=click.Path(exists=True))
@click.option("-m", "--meta", "meta_name", help="Metadata to update")
@click.option("-s", "--from-string", help="String value")
@click.option(
    "-e",
    "--encoder",
    type=click.Choice(["integer", "id"]),
    help="Encoder for value",
)
@click.option("-k", "--key-id", help="Set key ID (name or 0x hex)")
@click.option("-i", "--keystore-id", help="Set keystore ID (name or 0x hex)")
@_verbose_option
@_handle_error
def set_cmd(
    filename: str,
    meta_name: str | None,
    from_string: str | None,
    encoder: str | None,
    key_id: str | None,
    keystore_id: str | None,
    verbose: int,
) -> None:
    """Update metadata or header fields in a bpak file."""
    _apply_verbose(verbose)
    with _bpak.Package(filename, "r+") as pkg:
        if key_id is not None:
            pkg.key_id = resolve_id(key_id)

        if keystore_id is not None:
            pkg.keystore_id = resolve_id(keystore_id)

        if meta_name and from_string:
            meta_id = resolve_id(meta_name)

            if encoder:
                new_data = encode_meta_value(from_string, encoder)
            else:
                new_data = from_string.encode("ascii") + b"\x00"

            try:
                m = pkg.get_meta(meta_id)
                if len(new_data) <= m.size:
                    m.raw_data = new_data
                else:
                    part_ref = m.part_id_ref
                    m.delete()
                    pkg.add_meta(meta_id, part_ref, new_data)
            except _bpak.Error:
                pkg.add_meta(meta_id, 0, new_data)


# --- compare ---

RED_CLR = "\033[31m"
YEL_CLR = "\033[33m"
GRN_CLR = "\033[32m"
NO_CLR = "\033[0m"


@cli.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@_verbose_option
@_handle_error
def compare(file1: str, file2: str, verbose: int) -> None:
    """Compare two bpak files."""
    _apply_verbose(verbose)
    with _bpak.Package(file1, "rb") as pkg1, _bpak.Package(file2, "rb") as pkg2:
        click.echo("Metadata:")
        meta1 = {(m.id, m.part_id_ref): m for m in pkg1.meta}
        meta2 = {(m.id, m.part_id_ref): m for m in pkg2.meta}

        all_keys = sorted(set(meta1.keys()) | set(meta2.keys()))
        for key in all_keys:
            m1 = meta1.get(key)
            m2 = meta2.get(key)
            mid, mref = key
            id_name = _bpak.id_to_string(mid) or ""

            if m1 and m2:
                if m1.raw_data == m2.raw_data:
                    sym = "="
                    clr = NO_CLR
                else:
                    sym = "*"
                    clr = YEL_CLR
            elif m1:
                sym = "-"
                clr = RED_CLR
            else:
                sym = "+"
                clr = GRN_CLR

            click.echo(
                f"  {clr}{sym} {mid:08x}  {id_name:<20s}  "
                f"ref={mref:08x}{NO_CLR}"
            )

        click.echo("\nParts:")
        parts1 = {p.id: p for p in pkg1.parts}
        parts2 = {p.id: p for p in pkg2.parts}

        all_ids = sorted(set(parts1.keys()) | set(parts2.keys()))
        for pid in all_ids:
            p1 = parts1.get(pid)
            p2 = parts2.get(pid)

            if p1 and p2:
                if p1.size == p2.size:
                    sym = "="
                    clr = NO_CLR
                else:
                    sym = "*"
                    clr = YEL_CLR
            elif p1:
                sym = "-"
                clr = RED_CLR
            else:
                sym = "+"
                clr = GRN_CLR

            size = (p1 or p2).size
            click.echo(f"  {clr}{sym} {pid:08x}  size={size}{NO_CLR}")


# --- extract ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-p", "--part", "part_name", help="Extract part")
@click.option("-m", "--meta", "meta_name", help="Extract metadata")
@click.option("-o", "--output", type=click.Path(), help="Output file")
@click.option("-r", "--part-ref", help="Part reference for metadata")
@_verbose_option
@_handle_error
def extract(
    filename: str,
    part_name: str | None,
    meta_name: str | None,
    output: str | None,
    part_ref: str | None,
    verbose: int,
) -> None:
    """Extract parts or metadata from a bpak file."""
    _apply_verbose(verbose)
    if not part_name and not meta_name:
        raise click.UsageError("Must specify --part or --meta")
    if part_name and meta_name:
        raise click.UsageError("Specify only one of --part or --meta")

    with _bpak.Package(filename, "rb") as pkg:
        if part_name:
            part_id = resolve_id(part_name)
            if output:
                pkg.extract_file(part_id, output)
            else:
                p = pkg.get_part(part_id)
                data = p.read_data()
                sys.stdout.buffer.write(data)

        elif meta_name:
            meta_id = resolve_id(meta_name)
            ref_id = resolve_id(part_ref) if part_ref else 0
            m = pkg.get_meta(meta_id, ref_id)
            data = m.raw_data

            if output:
                Path(output).write_bytes(data)
            else:
                sys.stdout.buffer.write(data)


# --- delete ---


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-p", "--part", "part_name", help="Part to delete")
@click.option("-a", "--all", "delete_all", is_flag=True, help="Delete all parts")
@click.option(
    "-k", "--keep-meta", is_flag=True, help="Keep metadata when deleting parts"
)
@_verbose_option
@_handle_error
def delete(
    filename: str,
    part_name: str | None,
    delete_all: bool,
    keep_meta: bool,
    verbose: int,
) -> None:
    """Delete parts from a bpak file."""
    _apply_verbose(verbose)
    if not part_name and not delete_all:
        raise click.UsageError("Must specify --part or --all")
    if part_name and delete_all:
        raise click.UsageError("Specify only one of --part or --all")

    with _bpak.Package(filename, "r+") as pkg:
        if delete_all:
            pkg.delete_all_parts(keep_meta=keep_meta)
        elif part_name:
            part_id = resolve_id(part_name)
            p = pkg.get_part(part_id)
            p.delete(keep_meta=keep_meta)


if __name__ == "__main__":
    cli()
