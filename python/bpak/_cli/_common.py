"""Shared plumbing for the bpak CLI."""

from __future__ import annotations

import functools
import re
import sys
from typing import Any, Callable, Iterable

import click

from .. import _bpak
from .._helpers import resolve_id

BPAK_METADATA_BYTES = getattr(_bpak, "BPAK_METADATA_BYTES", 1920)
BPAK_MAX_SIGNATURE_BYTES = getattr(_bpak, "BPAK_MAX_SIGNATURE_BYTES", 512)

_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class BpakId(click.ParamType):
    name = "bpak_id"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            return resolve_id(value)
        except Exception as exc:
            self.fail(f"{value!r} is not a valid bpak id ({exc})", param, ctx)


BPAK_ID = BpakId()


def _log_callback_factory(ctx: click.Context) -> Callable[[int, str], None]:
    def _cb(level: int, msg: str) -> None:
        v = ctx.obj.get("verbose", 0)
        if level == 0 or level <= v:
            click.echo(msg, nl=False, err=True)
    return _cb


def install_verbose(ctx: click.Context, verbose: int) -> None:
    """Wire the _bpak log callback for this invocation and tear it down on exit."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    if verbose > 0:
        _bpak.set_log_func(_log_callback_factory(ctx))
    else:
        _bpak.set_log_func(None)
    ctx.call_on_close(lambda: _bpak.set_log_func(None))


def open_package(mode: str = "rb"):
    """Decorator that opens the package file, passes pkg as first arg, closes it,
    and translates _bpak.Error to ClickException.

    The decorated callback must have signature (pkg, ...); Click's own argument
    injection keeps working for everything after pkg.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(filename: str, *args: Any, **kwargs: Any) -> Any:
            try:
                with _bpak.Package(filename, mode) as pkg:
                    return func(pkg, *args, **kwargs)
            except _bpak.Error as exc:
                raise click.ClickException(str(exc)) from exc
        return wrapper
    return decorator


def handle_bpak_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Translate _bpak.Error to ClickException for commands that manage their
    own Package open/close (e.g. commands that open two packages)."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except _bpak.Error as exc:
            raise click.ClickException(str(exc)) from exc
    return wrapper


def _is_set(value: Any) -> bool:
    """Is this parsed option "set" for validation purposes?

    Accept 0 / "" / False-only-if-it-came-from-an-explicit-false as "set",
    since Click only yields the default otherwise. A `None` means the option
    was never provided; a `False` bool flag is likewise unset (the absence
    of an `is_flag=True` flag).
    """
    if value is None:
        return False
    if value is False:
        return False
    return True


def exactly_one_of(values: dict[str, Any]) -> str:
    """Return the one option name whose value is set, or raise UsageError."""
    set_names = [name for name, v in values.items() if _is_set(v)]
    if len(set_names) == 0:
        raise click.UsageError(
            f"one of {', '.join(values.keys())} is required"
        )
    if len(set_names) > 1:
        raise click.UsageError(
            f"only one of {', '.join(values.keys())} is allowed "
            f"(got: {', '.join(set_names)})"
        )
    return set_names[0]


def at_least_one_of(values: dict[str, Any]) -> None:
    if not any(_is_set(v) for v in values.values()):
        raise click.UsageError(
            f"at least one of {', '.join(values.keys())} is required"
        )


def incompatible(values: dict[str, Any]) -> None:
    set_names = [k for k, v in values.items() if _is_set(v)]
    if len(set_names) > 1:
        raise click.UsageError(
            f"{', '.join(values.keys())} are mutually exclusive "
            f"(got: {', '.join(set_names)})"
        )


def binary_sink(output_path: str | None):
    """Return a writable binary stream.

    - output_path given: file opened for writing (caller is responsible for closing).
    - output_path None: sys.stdout.buffer, but only when stdout is non-TTY;
      otherwise UsageError to prevent terminal corruption.
    """
    if output_path is not None:
        return open(output_path, "wb")
    if sys.stdout.isatty():
        raise click.UsageError(
            "refusing to write binary data to a terminal; "
            "redirect stdout or pass --output PATH"
        )
    return sys.stdout.buffer


def safe_c_identifier(name: str) -> str:
    if not _C_IDENTIFIER_RE.match(name):
        raise click.UsageError(
            f"{name!r} is not a valid C identifier "
            "(expected [A-Za-z_][A-Za-z0-9_]*)"
        )
    return name


def bin2hex(data: bytes) -> str:
    return data.hex()


def flag_str(flags: int) -> str:
    chars = list("--------")
    if flags & _bpak.FLAG_EXCLUDE_FROM_HASH:
        chars[0] = "h"
    if flags & _bpak.FLAG_TRANSPORT:
        chars[1] = "T"
    return "".join(chars)
