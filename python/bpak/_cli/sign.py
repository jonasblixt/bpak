"""`bpak sign` and `bpak verify`."""

from __future__ import annotations

from pathlib import Path

import click

from ._common import (
    BPAK_MAX_SIGNATURE_BYTES,
    exactly_one_of,
    handle_bpak_errors,
    open_package,
)


@click.command()
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--key",
    "key_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Private key (PEM) used to sign the package",
)
@click.option(
    "--signature",
    "signature_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Pre-computed signature file to install instead of signing",
)
@handle_bpak_errors
@open_package("r+")
def sign(pkg, key_path: str | None, signature_path: str | None) -> None:
    """Sign a bpak file."""
    choice = exactly_one_of({"--key": key_path, "--signature": signature_path})
    if choice == "--signature":
        sig_data = Path(signature_path).read_bytes()
        if len(sig_data) > BPAK_MAX_SIGNATURE_BYTES:
            raise click.ClickException(
                f"Signature file too large "
                f"({len(sig_data)} > {BPAK_MAX_SIGNATURE_BYTES} bytes)"
            )
        pkg.signature = sig_data
    else:
        pkg.sign(key_path)


@click.command()
@click.argument("filename", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--key",
    "key_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Public key (PEM) to verify against",
)
@click.option(
    "--keystore",
    "keystore_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Keystore bpak file to verify against",
)
@handle_bpak_errors
@open_package("rb")
def verify(pkg, key_path: str | None, keystore_path: str | None) -> None:
    """Verify a bpak file signature."""
    choice = exactly_one_of(
        {"--key": key_path, "--keystore": keystore_path}
    )
    if choice == "--keystore":
        pkg.verify_with_keystore(keystore_path)
    else:
        pkg.verify(key_path)
    click.echo("Verification OK")
