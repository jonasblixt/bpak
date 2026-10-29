"""BPAK command line tool.

The options and the output are compatible with the C implementation of the
tool that this replaces. Errors from the library exit with the negated
'enum bpak_errors' value, '-error & 0xff', errors from other files with
BPAK_FAILED and usage errors with 2.
"""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import re
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

import click

import bpak

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

HASH_KINDS = {
    "sha256": bpak.HASH_SHA256,
    "sha384": bpak.HASH_SHA384,
    "sha512": bpak.HASH_SHA512,
}

SIGNATURE_KINDS = {
    "prime256v1": bpak.SIGN_PRIME256v1,
    "secp384r1": bpak.SIGN_SECP384r1,
    "secp521r1": bpak.SIGN_SECP521r1,
    "rsa4096": bpak.SIGN_RSA4096,
}

# 'enum bpak_key_kind' names for the generated keystore code
KEY_KINDS = {
    bpak.KEY_PUB_RSA4096: "BPAK_KEY_PUB_RSA4096",
    bpak.KEY_PUB_PRIME256v1: "BPAK_KEY_PUB_PRIME256v1",
    bpak.KEY_PUB_SECP384r1: "BPAK_KEY_PUB_SECP384r1",
    bpak.KEY_PUB_SECP521r1: "BPAK_KEY_PUB_SECP521r1",
}

INTEGER_SIZE = 8
ID_SIZE = 4

# Integers are parsed like strtol() with base 0: hex with '0x', octal with a
# leading '0', otherwise decimal
_INTEGER_RE = re.compile(r"\s*([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)\s*")
_HEX_ID_RE = re.compile(r"0x([0-9a-fA-F]+)")

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class _Settings:
    verbosity: int = 0

    def log(self, level: int, message: str) -> None:
        """Log function for the library, 'message' includes the newline."""
        if level == 0:
            click.echo(message, nl=False, err=True)
        elif level <= self.verbosity:
            click.echo(message, nl=False)


def _verbose(message: str, level: int = 1) -> None:
    settings = click.get_current_context().find_object(_Settings)
    if settings is not None and level <= settings.verbosity:
        click.echo(message)


def _add_verbosity(ctx: click.Context, _param: click.Parameter, value: int) -> None:
    ctx.ensure_object(_Settings).verbosity += value


def verbose_option(f: F) -> F:
    """-v for every command, it can be given before or after the command."""
    return click.option(
        "-v",
        "--verbose",
        count=True,
        expose_value=False,
        callback=_add_verbosity,
        help="Verbose output, repeat for more details.",
    )(f)


# click.ParamType is generic since click 8.2
if TYPE_CHECKING:
    _IntParamType = click.ParamType[int]
else:
    _IntParamType = click.ParamType


class BpakIdType(_IntParamType):
    """A bpak id given as a name, which is translated to an id, or as hex."""

    name = "id"

    def convert(
        self,
        value: Any,  # noqa: ANN401
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> int:
        """Convert a name or a hex id to an id."""
        if isinstance(value, int):
            return value

        m = _HEX_ID_RE.fullmatch(value)
        if m is not None:
            bpak_id = int(m.group(1), 16)
            if bpak_id > 0xFFFFFFFF:  # noqa: PLR2004
                self.fail(f"{value} is larger than 32 bits", param, ctx)
            return bpak_id

        return int(bpak.id(value))


BPAK_ID = BpakIdType()
PATH = click.Path(dir_okay=False, path_type=pathlib.Path)
EXISTING_PATH = click.Path(exists=True, dir_okay=False, path_type=pathlib.Path)


class CommandError(click.ClickException):
    """A library error, exits with the negated error code like the C tool."""

    def __init__(self, error: bpak.Error) -> None:
        """Create a command error from a library error."""
        super().__init__(str(error))
        self.exit_code = -error.code & 0xFF  # type: ignore[misc]


class BpakGroup(click.Group):
    """Command group that turns library and file errors into command errors."""

    def invoke(self, ctx: click.Context) -> Any:  # noqa: ANN401
        """Invoke the command, library errors exit with their error code."""
        try:
            return super().invoke(ctx)
        except bpak.Error as e:
            raise CommandError(e) from e
        except OSError as e:
            # Files the tool reads or writes itself, the C tool failed with
            # BPAK_FAILED
            raise CommandError(bpak.FailedError(str(e))) from e


def _parse_integer(text: str, param_hint: str) -> int:
    """Parse an integer and return it as an unsigned 64 bit value."""
    m = _INTEGER_RE.fullmatch(text)
    if m is None:
        msg = f"'{text}' is not a number"
        raise click.BadParameter(msg, param_hint=param_hint)

    sign, digits = m.groups()
    if digits[:2].lower() == "0x":
        value = int(digits, 16)
    elif digits.startswith("0"):
        value = int(digits, 8)
    else:
        value = int(digits, 10)

    if sign == "-":
        value = -value

    if not -(2**63) <= value < 2**63:
        msg = f"'{text}' does not fit in 64 bits"
        raise click.BadParameter(msg, param_hint=param_hint)

    return value & 0xFFFFFFFFFFFFFFFF


def _string_data(text: str) -> bytes:
    """Strings are stored with a terminating NUL, as given on the command line."""
    return os.fsencode(text) + b"\0"


def _get_meta(pkg: bpak.Package, meta_id: int, part_ref: int = 0) -> bpak.Meta:
    try:
        return pkg.get_meta(meta_id, part_ref)
    except KeyError:
        msg = f"Could not find meta data {meta_id:08x}"
        if part_ref:
            msg += f" for part {part_ref:08x}"
        raise bpak.NotFoundError(msg) from None


def _get_part(pkg: bpak.Package, part_id: int) -> bpak.Part:
    try:
        return pkg.get_part(part_id)
    except KeyError:
        msg = f"Could not find part {part_id:08x}"
        raise bpak.NotFoundError(msg) from None


def _part_flags(part: bpak.Part) -> str:
    return (
        ("h" if part.flags & bpak.FLAG_EXCLUDE_FROM_HASH else "-")
        + ("T" if part.flags & bpak.FLAG_TRANSPORT else "-")
        + "------"
    )


def _part_line(part: bpak.Part) -> str:
    transport_size = (
        part.transport_size if part.flags & bpak.FLAG_TRANSPORT else part.installed_size
    )
    return (
        f"{part.id:08x}   {part.installed_size:<12} {part.pad_bytes:<3}    "
        f"{_part_flags(part)}       {transport_size:<12}"
    )


def _meta_line(meta: bpak.Meta) -> str:
    return f"{meta.id:08x}   {meta.size:<3}    {bpak.id_to_string(meta.id):<20}"


# Values that are too small for their type are shown as invalid instead of
# failing the command
def _describe(meta: bpak.Meta) -> str:
    try:
        return meta.describe()
    except bpak.SizeError:
        return "<invalid>"


def _print_version(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        click.echo(f"BitPacker {bpak.version()}")
        ctx.exit()


@click.group(cls=BpakGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option(
    "-V",
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_print_version,
    help="Display version and exit.",
)
@verbose_option
@click.pass_context
def cli(ctx: click.Context) -> None:
    """BitPacker, create, sign, inspect and transport encode bpak packages.

    Parts and meta data are addressed by name, which is translated to an id,
    or by id written as hex with a '0x' prefix.
    """
    bpak.set_log_func(ctx.ensure_object(_Settings).log)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-Y", "--force", is_flag=True, help="Overwrite an existing file without asking.")
@click.option(
    "-H",
    "--hash-kind",
    type=click.Choice(list(HASH_KINDS)),
    default="sha256",
    show_default=True,
    help="Hash algorithm.",
)
@click.option(
    "-S",
    "--signature-kind",
    type=click.Choice(list(SIGNATURE_KINDS)),
    default="prime256v1",
    show_default=True,
    help="Signature algorithm.",
)
@verbose_option
def create(filename: pathlib.Path, force: bool, hash_kind: str, signature_kind: str) -> None:
    """Create an empty package."""
    if filename.exists() and not force:
        click.confirm(f"File '{filename}' already exists, overwrite?", abort=True)

    with bpak.Package(filename, "wb") as pkg:
        pkg.hash_kind = HASH_KINDS[hash_kind]
        pkg.signature_kind = SIGNATURE_KINDS[signature_kind]
        pkg.update_hash()
        pkg.write_header()


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-p", "--part", "part_name", help="Add a part with this name.")
@click.option("-m", "--meta", "meta_id", type=BPAK_ID, help="Add meta data with this id.")
@click.option("-f", "--from-file", type=EXISTING_PATH, help="Read the data from a file.")
@click.option("-s", "--from-string", help="Use a string as data.")
@click.option(
    "-e",
    "--encoder",
    type=click.Choice(["integer", "uuid", "id", "key", "merkle"]),
    help="Encode the data. integer, uuid and id are used with --from-string "
    "and store a 64 bit integer, a UUID or a bpak id. key and merkle are used "
    "with --from-file and add a DER encoded key or a part followed by its "
    "merkle hash tree.",
)
@click.option(
    "-F",
    "--set-flag",
    "flags",
    type=click.Choice(["dont-hash"]),
    multiple=True,
    help="Set a flag on the part. dont-hash excludes the part from the payload hash.",
)
@click.option(
    "-r", "--part-ref", type=BPAK_ID, default=0, help="Part that the meta data belongs to."
)
@verbose_option
def add(
    filename: pathlib.Path,
    part_name: str | None,
    meta_id: int | None,
    from_file: pathlib.Path | None,
    from_string: str | None,
    encoder: str | None,
    flags: tuple[str, ...],
    part_ref: int,
) -> None:
    """Add a part or meta data to a package."""
    if (part_name is None) == (meta_id is None):
        msg = "Select either --part or --meta"
        raise click.UsageError(msg)

    if (from_file is None) == (from_string is None):
        msg = "Select either --from-file or --from-string"
        raise click.UsageError(msg)

    with bpak.Package(filename, "r+") as pkg:
        if meta_id is not None:
            _add_meta(pkg, meta_id, part_ref, from_file, from_string, encoder)
        elif part_name is not None:
            _add_part(pkg, part_name, from_file, encoder, flags)


def _add_meta(
    pkg: bpak.Package,
    meta_id: int,
    part_ref: int,
    from_file: pathlib.Path | None,
    from_string: str | None,
    encoder: str | None,
) -> None:
    if encoder in ("key", "merkle"):
        msg = f"The {encoder} encoder can only be used with --part"
        raise click.UsageError(msg)

    if from_string is not None:
        param_hint = "--from-string"
        data = _string_data(from_string)
        if len(data) > bpak.METADATA_BYTES:
            msg = "The string does not fit in the meta data area"
            raise bpak.NoSpaceLeftError(msg)
    else:
        assert from_file is not None  # noqa: S101
        param_hint = "--from-file"
        with from_file.open("rb") as f:
            data = f.read(bpak.METADATA_BYTES)
        if not data:
            msg = f"{from_file} is empty"
            raise bpak.FailedError(msg)

    # Encoders interpret the input as a string
    text = os.fsdecode(data.split(b"\0", 1)[0])

    if encoder == "uuid":
        try:
            data = uuid.UUID(text).bytes
        except ValueError:
            msg = f"'{text}' is not a UUID"
            raise click.BadParameter(msg, param_hint=param_hint) from None
    elif encoder == "integer":
        data = _parse_integer(text, param_hint).to_bytes(INTEGER_SIZE, "little")
    elif encoder == "id":
        data = bpak.id(text).to_bytes(ID_SIZE, "little")

    _verbose(f"Adding meta data {meta_id:08x}, {len(data)} bytes")
    pkg.add_meta(meta_id, part_ref, data=data)


def _add_part(
    pkg: bpak.Package,
    part_name: str,
    from_file: pathlib.Path | None,
    encoder: str | None,
    flags: tuple[str, ...],
) -> None:
    if from_file is None:
        msg = "Parts must be added with --from-file"
        raise click.UsageError(msg)

    if encoder not in (None, "key", "merkle"):
        msg = f"The {encoder} encoder can only be used with --meta"
        raise click.UsageError(msg)

    part_flags = bpak.FLAG_EXCLUDE_FROM_HASH if "dont-hash" in flags else 0

    _verbose(f"Adding part {part_name} from {from_file}")
    if encoder == "key":
        pkg.add_key(part_name, from_file, flags=part_flags)
    else:
        pkg.add_file(part_name, from_file, with_merkle_tree=encoder == "merkle", flags=part_flags)


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-p", "--part", "part_id", type=BPAK_ID, help="Delete this part.")
@click.option("-a", "--all", "delete_all", is_flag=True, help="Delete all parts.")
@click.option(
    "-k", "--keep-meta", is_flag=True, help="Keep the meta data that belongs to the parts."
)
@verbose_option
def delete(filename: pathlib.Path, part_id: int | None, delete_all: bool, keep_meta: bool) -> None:
    """Delete parts from a package.

    --all deletes all parts, also when --part is given.
    """
    if part_id is None and not delete_all:
        msg = "Select either --part or --all"
        raise click.UsageError(msg)

    with bpak.Package(filename, "r+") as pkg:
        if delete_all:
            pkg.delete_all_parts(remove_meta=not keep_meta)
        elif part_id is not None:
            pkg.delete_part(part_id, remove_meta=not keep_meta)


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-a", "--add", "add_rule", is_flag=True, help="Add a transport rule for a part.")
@click.option("-E", "--encode", is_flag=True, help="Transport encode the package.")
@click.option("-D", "--decode", is_flag=True, help="Decode a transport encoded package.")
@click.option(
    "-p",
    "--part",
    "-r",
    "--part-ref",
    "part_ref",
    type=BPAK_ID,
    default=0,
    help="Part that the transport rule applies to.",
)
@click.option("-e", "--encoder", type=BPAK_ID, help="Encoder of the transport rule.")
@click.option("-d", "--decoder", type=BPAK_ID, help="Decoder of the transport rule.")
@click.option(
    "-O",
    "--origin",
    type=EXISTING_PATH,
    help="Package that the encoder diffs against and the decoder patches.",
)
@click.option("-o", "--output", type=PATH, help="Output package of --encode and --decode.")
@verbose_option
def transport(
    filename: pathlib.Path,
    add_rule: bool,
    encode: bool,
    decode: bool,
    part_ref: int,
    encoder: int | None,
    decoder: int | None,
    origin: pathlib.Path | None,
    output: pathlib.Path | None,
) -> None:
    """Transport encoding and decoding.

    --add adds a transport rule, the encoder and decoder that are used for a
    part.

    --encode encodes a package for transport according to its rules, --decode
    decodes it again. Encoders that create a diff need the --origin package
    that the receiver already has.
    """
    if add_rule + encode + decode != 1:
        msg = "Select one of --add, --encode or --decode"
        raise click.UsageError(msg)

    if add_rule:
        if encoder is None or decoder is None:
            msg = "--add requires --encoder and --decoder"
            raise click.UsageError(msg)

        with bpak.Package(filename, "rb+") as pkg:
            pkg.add_transport_meta(part_ref, encoder, decoder)
        return

    if output is None:
        msg = "--encode and --decode require --output"
        raise click.UsageError(msg)

    func = bpak.transport_encode if encode else bpak.transport_decode
    with (
        bpak.Package(filename, "rb+") as input_pkg,
        bpak.Package(origin, "rb+")
        if origin is not None
        else contextlib.nullcontext() as origin_pkg,
        bpak.Package(output, "wb+") as output_pkg,
    ):
        func(input_pkg, output_pkg, origin_pkg)


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-k", "--key", type=EXISTING_PATH, help="Sign with this private key.")
@click.option(
    "-f",
    "--signature",
    type=EXISTING_PATH,
    help="Write a signature that was created elsewhere, see 'show --binary-hash'.",
)
@verbose_option
def sign(filename: pathlib.Path, key: pathlib.Path | None, signature: pathlib.Path | None) -> None:
    """Sign a package."""
    if (key is None) == (signature is None):
        msg = "Select either --key or --signature"
        raise click.UsageError(msg)

    with bpak.Package(filename, "r+") as pkg:
        if signature is not None:
            data = signature.read_bytes()
            _verbose(f"Loaded signature {len(data)} bytes")
            pkg.signature = data
        elif key is not None:
            pkg.sign(key)


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-k", "--key", type=EXISTING_PATH, help="Verify with this public key.")
@click.option(
    "-K",
    "--keystore",
    type=EXISTING_PATH,
    help="Verify with the key from a keystore that the key-id of the package selects.",
)
@verbose_option
def verify(filename: pathlib.Path, key: pathlib.Path | None, keystore: pathlib.Path | None) -> None:
    """Verify the signature and the payload of a package."""
    if (key is None) == (keystore is None):
        msg = "Select either --key or --keystore"
        raise click.UsageError(msg)

    with bpak.Package(filename, "rb") as pkg:
        if key is not None:
            pkg.verify(key)
        else:
            pkg.verify(keystore_path=keystore)

    click.echo("Verification OK")


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-m", "--meta", "meta_id", type=BPAK_ID, help="Show meta data.")
@click.option(
    "-p", "--part", "part_id", type=BPAK_ID, help="Show a part, or the part reference of --meta."
)
@click.option("-P", "--part-hash", type=BPAK_ID, help="Print the SHA-256 hash of a part.")
@click.option("-H", "--hash", "text_hash", is_flag=True, help="Print the package hash.")
@click.option(
    "-B",
    "--binary-hash",
    is_flag=True,
    help="Write the binary package hash to stdout, this is what gets signed.",
)
@verbose_option
def show(
    filename: pathlib.Path,
    meta_id: int | None,
    part_id: int | None,
    part_hash: int | None,
    text_hash: bool,
    binary_hash: bool,
) -> None:
    """Show information about a package.

    Without options an overview of the package is shown.
    """
    with bpak.Package(filename, "rb") as pkg:
        if meta_id is not None:
            for meta in pkg.meta:
                if meta.id == meta_id and part_id in (None, meta.part_id_ref):
                    description = meta.describe()
                    if description:
                        click.echo(description)
                    return
            msg = f"Could not find meta data {meta_id:08x}"
            raise bpak.MissingMetaDataError(msg)

        if part_id is not None:
            part = _get_part(pkg, part_id)
            click.echo(f"Found 0x{part.id:x}, {part.installed_size} bytes")
        elif part_hash is not None:
            click.echo(pkg.part_sha256(part_hash).hex())
        elif binary_hash:
            sys.stdout.buffer.write(pkg.update_hash())
        elif text_hash:
            click.echo(pkg.update_hash().hex())
        else:
            _show_package(filename, pkg)


def _show_package(filename: pathlib.Path, pkg: bpak.Package) -> None:
    click.echo(f"BPAK File: {filename}")
    click.echo()
    click.echo(f"Hash:        {bpak.hash_kind_to_string(pkg.hash_kind)}")
    click.echo(f"Signature:   {bpak.signature_kind_to_string(pkg.signature_kind)}")
    click.echo(f"Key ID:      {pkg.key_id:08x}")
    click.echo(f"Keystore ID: {pkg.keystore_id:08x}")

    click.echo("\nMetadata:")
    click.echo("    ID         Size   Meta ID              Part Ref   Data")
    for meta in pkg.meta:
        part_ref = f"{meta.part_id_ref:08x}" if meta.part_id_ref else " " * 8
        click.echo(f"    {_meta_line(meta)} {part_ref}   {_describe(meta)}")

    click.echo("\nParts:")
    click.echo("    ID         Size         Z-pad  Flags          Transport Size")
    for part in pkg.parts:
        click.echo(f"    {_part_line(part)}")

    stored_payload_hash = pkg.payload_hash
    header_hash = pkg.update_hash()
    click.echo(f"\nHeader hash:  {header_hash.hex()}")
    click.echo(f"Payload hash: {pkg.payload_hash.hex()}")

    if pkg.payload_hash != stored_payload_hash:
        click.echo("Warning: Computed payload hash does not match payload hash in header")

    _verbose(f"Metadata usage: {sum(m.size for m in pkg.meta)}/{bpak.METADATA_BYTES} bytes")
    _verbose(f"Transport size: {pkg.size} bytes")
    _verbose(f"Installed size: {pkg.installed_size} bytes")


@cli.command("set")
@click.argument("filename", type=PATH)
@click.option("-m", "--meta", "meta_id", type=BPAK_ID, help="Update meta data.")
@click.option("-s", "--from-string", help="New value of the meta data.")
@click.option(
    "-e",
    "--encoder",
    type=click.Choice(["integer", "id"]),
    help="Encode the value as a 64 bit integer or a bpak id.",
)
@click.option(
    "-r", "--part-ref", type=BPAK_ID, default=0, help="Part that the meta data belongs to."
)
@click.option("-k", "--key-id", type=BPAK_ID, help="Set the key id.")
@click.option("-i", "--keystore-id", type=BPAK_ID, help="Set the keystore id.")
@verbose_option
def set_(
    filename: pathlib.Path,
    meta_id: int | None,
    from_string: str | None,
    encoder: str | None,
    part_ref: int,
    key_id: int | None,
    keystore_id: int | None,
) -> None:
    """Update meta data, the key id or the keystore id."""
    if meta_id is None and key_id is None and keystore_id is None:
        msg = "Select --meta, --key-id or --keystore-id"
        raise click.UsageError(msg)

    if meta_id is not None and from_string is None:
        msg = "--meta requires --from-string"
        raise click.UsageError(msg)

    with bpak.Package(filename, "r+") as pkg:
        if meta_id is not None:
            assert from_string is not None  # noqa: S101
            meta = _get_meta(pkg, meta_id, part_ref)

            if encoder is None:
                meta.raw_data = _string_data(from_string)
            elif encoder == "integer":
                if meta.size != INTEGER_SIZE:
                    msg = f"Meta data {meta_id:08x} is {meta.size} bytes, not an integer"
                    raise bpak.SizeError(msg)
                value = _parse_integer(from_string, "--from-string")
                meta.raw_data = value.to_bytes(INTEGER_SIZE, "little")
            else:
                if meta.size != ID_SIZE:
                    msg = f"Meta data {meta_id:08x} is {meta.size} bytes, not an id"
                    raise bpak.SizeError(msg)
                meta.raw_data = bpak.id(from_string).to_bytes(ID_SIZE, "little")

        if key_id is not None:
            _verbose(f"Setting key-id to       0x{key_id:08x}")
            pkg.key_id = key_id

        if keystore_id is not None:
            _verbose(f"Setting keystore-id to  0x{keystore_id:08x}")
            pkg.keystore_id = keystore_id


@cli.group(context_settings=CONTEXT_SETTINGS)
@verbose_option
def generate() -> None:
    """Generate ids and keystore code."""


@generate.command("id")
@click.argument("string")
@verbose_option
def generate_id(string: str) -> None:
    """Translate a string to a bpak id."""
    click.echo(f'id("{string}") = 0x{bpak.id(string):08x}')


@generate.command("keystore")
@click.argument("filename", type=PATH)
@click.option("-n", "--name", required=True, help="Name of the keystore in the generated code.")
@click.option(
    "-d",
    "--decorate",
    is_flag=True,
    help="Place the keystore and the keys in the .keystore_header and .keystore_key sections.",
)
@verbose_option
def generate_keystore(filename: pathlib.Path, name: str, decorate: bool) -> None:
    """Generate C code for a keystore package."""
    with bpak.Package(filename, "rb") as pkg:
        _get_meta(pkg, bpak.id("bpak-package"))
        provider_id = int.from_bytes(
            _get_meta(pkg, bpak.id("keystore-provider-id")).raw_data[:ID_SIZE], "little"
        )
        keys = []
        for part in pkg.parts:
            kind, data = bpak.parse_public_key(part.read_data())
            if kind not in KEY_KINDS:
                msg = f"Key {part.id:08x} has an unsupported kind ({kind})"
                raise bpak.UnsupportedKeyError(msg)
            keys.append((part.id, kind, data))

    name = name.replace("-", "_")
    key_section = '__attribute__((section (".keystore_key"))) ' if decorate else ""
    header_section = '__attribute__((section (".keystore_header"))) ' if decorate else ""
    indent = "\n            "

    code = [
        f"/* Automatically generated with bpak {bpak.version()} */\n",
        "#include <bpak/bpak.h>\n",
        "#include <bpak/keystore.h>\n",
        "\n\n",
    ]

    for index, (key_id, kind, data) in enumerate(keys):
        key_bytes = "".join(
            f"0x{byte:02x}, " + (indent if (i + 1) % 8 == 0 else "") for i, byte in enumerate(data)
        )
        code += [
            f"const struct bpak_key keystore_{name}_key{index} {key_section}=\n",
            "{\n",
            f"    .id = 0x{key_id:x},\n",
            f"    .size = {len(data)},\n",
            f"    .kind = {KEY_KINDS[kind]},\n",
            "    .data =\n",
            "    {",
            indent,
            key_bytes,
            "\n    },\n",
            "};\n\n",
        ]

    code += [
        f"const struct bpak_keystore keystore_{name} {header_section}=\n",
        "{\n",
        f"    .id = 0x{provider_id:x},\n",
        f"    .no_of_keys = {len(keys)},\n",
        "    .verified = true,\n",
        "    .keys =\n",
        "    {\n",
        *(f"        (struct bpak_key *) &keystore_{name}_key{i},\n" for i in range(len(keys))),
        "    },\n",
        "};\n",
    ]

    click.echo("".join(code), nl=False)


@cli.command()
@click.argument("first", type=PATH)
@click.argument("second", type=PATH)
@verbose_option
def compare(first: pathlib.Path, second: pathlib.Path) -> None:
    """Compare the meta data and parts of two packages."""
    click.echo(f"BPAK comparison between:\n1: '{first}'\n2: '{second}'")
    click.echo()
    click.echo("=   : No difference")
    click.echo("+   : Exists in file 2 but not in file 1")
    click.echo("-   : Exists in file 1 but not in file 2")
    click.echo("*   : Exists in both but data differs\n")

    with bpak.Package(first, "rb") as pkg1, bpak.Package(second, "rb") as pkg2:
        click.echo("Metadata:")
        click.echo("    ID         Size   Meta ID              Data")

        meta2 = {(m.id, m.part_id_ref): m for m in pkg2.meta}
        for meta in pkg1.meta:
            other_meta = meta2.pop((meta.id, meta.part_id_ref), None)
            if other_meta is None:
                mark = "-"
            elif other_meta.raw_data != meta.raw_data:
                mark = "*"
            else:
                mark = "="
            _compare_line(mark, f"{_meta_line(meta)} {_describe(meta)}")

        for meta in meta2.values():
            _compare_line("+", f"{_meta_line(meta)} {_describe(meta)}")

        click.echo("\nParts:")
        click.echo("    ID         Size         Z-pad  Flags          Transport Size")

        parts2 = {p.id: p for p in pkg2.parts}
        for part in pkg1.parts:
            other_part = parts2.pop(part.id, None)
            if other_part is None:
                mark = "-"
            elif not _same_part(first, part, second, other_part):
                mark = "*"
            else:
                mark = "="
            _compare_line(mark, _part_line(part))

        for part in parts2.values():
            _compare_line("+", _part_line(part))


def _compare_line(mark: str, line: str) -> None:
    colors = {"*": "red", "-": "yellow", "+": "yellow"}
    click.secho(f"{mark}   {line}", fg=colors.get(mark), bold=mark in colors)


def _same_part(
    path1: pathlib.Path, part1: bpak.Part, path2: pathlib.Path, part2: bpak.Part
) -> bool:
    """Compare the part headers and the data as it is stored in the files."""

    def fields(p: bpak.Part) -> tuple[int, ...]:
        return (p.installed_size, p.transport_size, p.pad_bytes, p.flags, p.size)

    if fields(part1) != fields(part2):
        return False

    chunk_size = 64 * 1024
    with path1.open("rb") as f1, path2.open("rb") as f2:
        f1.seek(part1.offset)
        f2.seek(part2.offset)
        remaining = part1.size
        while remaining > 0:
            chunk = min(remaining, chunk_size)
            if f1.read(chunk) != f2.read(chunk):
                return False
            remaining -= chunk

    return True


@cli.command()
@click.argument("filename", type=PATH)
@click.option("-m", "--meta", "meta_id", type=BPAK_ID, help="Extract meta data.")
@click.option("-p", "--part", "part_id", type=BPAK_ID, help="Extract a part.")
@click.option(
    "-r", "--part-ref", type=BPAK_ID, default=0, help="Part that the meta data belongs to."
)
@click.option("-o", "--output", type=PATH, help="Output file (default: stdout).")
@verbose_option
def extract(
    filename: pathlib.Path,
    meta_id: int | None,
    part_id: int | None,
    part_ref: int,
    output: pathlib.Path | None,
) -> None:
    """Extract the data of a part or meta data.

    Transport encoded parts are extracted as they are stored, encoded.
    """
    if (meta_id is None) == (part_id is None):
        msg = "Select either --part or --meta"
        raise click.UsageError(msg)

    with bpak.Package(filename, "rb") as pkg:
        if part_id is not None and output is not None:
            pkg.extract_file(part_id, output)
            return

        if part_id is not None:
            data = _get_part(pkg, part_id).read_data()
        else:
            assert meta_id is not None  # noqa: S101
            data = _get_meta(pkg, meta_id, part_ref).raw_data

    if output is not None:
        output.write_bytes(data)
    else:
        sys.stdout.buffer.write(data)


@cli.command()
def completion() -> None:
    """Shell completion."""
    help_text = """
    bpak supports shell completions for bash, zsh and fish. Put one of the
    following lines in the appropriate .rc -file to enable shell completions.

    bash:
        eval "$(_BPAK_COMPLETE=bash_source bpak)"

    zsh:
        eval "$(_BPAK_COMPLETE=zsh_source bpak)"

    fish:
        _BPAK_COMPLETE=fish_source bpak | source
    """
    click.echo(help_text)


def main() -> None:
    """Entry point of the bpak tool."""
    # File names that are not valid in the file system encoding are printed
    # as the bytes they are, like the C tool did
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="surrogateescape")

    cli(prog_name="bpak")
