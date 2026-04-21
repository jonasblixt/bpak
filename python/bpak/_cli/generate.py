"""`bpak generate` group — id and keystore code generation."""

from __future__ import annotations

import struct

import click

from .. import _bpak
from ._common import handle_bpak_errors, safe_c_identifier


@click.group()
def generate() -> None:
    """Code and ID generation utilities."""


@generate.command("id")
@click.argument("string")
def generate_id(string: str) -> None:
    """Translate a string to its bpak id (32-bit CRC)."""
    click.echo(f'id("{string}") = 0x{_bpak.id(string):08x}')


_KEY_KIND_NAMES = {
    _bpak.KEY_PUB_PRIME256v1: "BPAK_KEY_PUB_PRIME256v1",
    _bpak.KEY_PUB_SECP384r1: "BPAK_KEY_PUB_SECP384r1",
    _bpak.KEY_PUB_SECP521r1: "BPAK_KEY_PUB_SECP521r1",
    _bpak.KEY_PUB_RSA4096: "BPAK_KEY_PUB_RSA4096",
}


@generate.command("keystore")
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--name",
    required=True,
    help="C identifier prefix for the generated keystore symbols",
)
@click.option(
    "--decorate",
    is_flag=True,
    help="Add .keystore_key/.keystore_header section attributes",
)
@handle_bpak_errors
def generate_keystore(filename: str, name: str, decorate: bool) -> None:
    """Emit a C keystore source file from a bpak keystore package."""
    safe = safe_c_identifier(name)

    try:
        from importlib.metadata import version as pkg_version
        ver = pkg_version("bpak")
    except Exception:
        ver = "unknown"

    with _bpak.Package(filename, "rb") as pkg:
        ks_meta = pkg.get_meta(_bpak.id("keystore-provider-id"))
        raw = ks_meta.raw_data
        if len(raw) < 4:
            raise click.ClickException(
                "keystore-provider-id metadata is too short "
                f"({len(raw)} bytes; need >= 4)"
            )
        ks_provider_id = struct.unpack("<I", raw[:4])[0]

        out = click.echo
        out(f"/* Automatically generated with bpak {ver} */")
        out("#include <bpak/bpak.h>")
        out("#include <bpak/keystore.h>")
        out("")

        key_decorator = '__attribute__((section (".keystore_key"))) '
        header_decorator = '__attribute__((section (".keystore_header"))) '

        key_index = 0
        for p in pkg.parts:
            data = p.read_data()
            kind, key_data = _bpak.parse_public_key(data)
            if kind not in _KEY_KIND_NAMES:
                raise click.ClickException(
                    f"Unsupported key type ({kind}) for part 0x{p.id:x}"
                )

            out(
                f"const struct bpak_key keystore_{safe}_key{key_index} "
                f"{key_decorator if decorate else ''}="
            )
            out("{")
            out(f"    .id = 0x{p.id:x},")
            out(f"    .size = {len(key_data)},")
            out(f"    .kind = {_KEY_KIND_NAMES[kind]},")
            out("    .data =")
            out("    {")
            line = "            "
            for i, b in enumerate(key_data):
                line += f"0x{b:02x}, "
                if (i + 1) % 8 == 0:
                    out(line)
                    line = "            "
            if line.strip():
                out(line)
            out("    },")
            out("};")
            out("")
            key_index += 1

        out(
            f"const struct bpak_keystore keystore_{safe} "
            f"{header_decorator if decorate else ''}="
        )
        out("{")
        out(f"    .id = 0x{ks_provider_id:x},")
        out(f"    .no_of_keys = {key_index},")
        out("    .verified = true,")
        out("    .keys =")
        out("    {")
        for i in range(key_index):
            out(f"        (struct bpak_key *) &keystore_{safe}_key{i},")
        out("    },")
        out("};")
