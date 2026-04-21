"""bpak CLI root group."""

from __future__ import annotations

import sys

import click

from ._common import install_verbose


def _print_version(ctx: click.Context, _param: click.Option, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    try:
        from importlib.metadata import version
        ver = version("bpak")
    except Exception:
        ver = "unknown"
    click.echo(f"BitPacker {ver}")
    ctx.exit(0)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-V",
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_print_version,
    help="Display version and exit",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (repeatable)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: int) -> None:
    """BPAK - Bit Packer."""
    install_verbose(ctx, verbose)


# Wire subcommands. Imports are deferred here so a command file can import
# from ._common without a circular dependency on this module.
from . import create as _create  # noqa: E402
from . import compare as _compare  # noqa: E402
from . import show as _show  # noqa: E402
from . import add as _add  # noqa: E402
from . import set as _set  # noqa: E402
from . import delete as _delete  # noqa: E402
from . import extract as _extract  # noqa: E402
from . import sign as _sign  # noqa: E402
from . import transport as _transport  # noqa: E402
from . import generate as _generate  # noqa: E402

cli.add_command(_create.create)
cli.add_command(_compare.compare)
cli.add_command(_show.show)
cli.add_command(_add.add)
cli.add_command(_set.set_)
cli.add_command(_delete.delete)
cli.add_command(_extract.extract)
cli.add_command(_sign.sign)
cli.add_command(_sign.verify)
cli.add_command(_transport.transport)
cli.add_command(_generate.generate)
