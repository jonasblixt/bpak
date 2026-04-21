#!/usr/bin/env python3
"""Argv-level tests for the bpak Python CLI (``bpak._cli``).

Run from ``${CMAKE_BINARY_DIR}/test`` with the source tree passed as argv[1]
(same convention as the other test_python_*.py scripts)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "../python/")

from click.testing import CliRunner  # noqa: E402

from bpak._cli import cli  # noqa: E402


# --- small helpers ---


def run(*args: str, input_: str | None = None):
    runner = CliRunner()
    return runner.invoke(cli, list(args), input=input_, catch_exceptions=False)


def ok(result, *, exit_code: int = 0) -> None:
    if result.exit_code != exit_code:
        raise AssertionError(
            f"expected exit {exit_code}, got {result.exit_code}\n"
            f"output:\n{result.output}"
        )


def fail(result, expected_fragment: str) -> None:
    assert result.exit_code != 0, f"expected failure, got 0\n{result.output}"
    if expected_fragment not in result.output:
        raise AssertionError(
            f"expected {expected_fragment!r} in output; got:\n{result.output}"
        )


def _make_keypair(tmp: Path) -> tuple[Path, Path]:
    priv = tmp / "priv.pem"
    pub = tmp / "pub.pem"
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
         "-out", str(priv)],
        check=True, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "ec", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True, stderr=subprocess.DEVNULL,
    )
    return priv, pub


# --- tests ---


def test_help_lists_all_top_level_commands():
    result = run("--help")
    ok(result)
    for cmd in ("create", "add", "show", "set", "delete", "extract",
                "sign", "verify", "compare", "transport", "generate"):
        assert cmd in result.output, f"missing top-level command: {cmd}"


def test_generate_id():
    result = run("generate", "id", "hello")
    ok(result)
    assert "0xf032519b" in result.output


def test_generate_keystore_rejects_bad_identifier(tmp_path: Path):
    pkg = tmp_path / "ks.bpak"
    ok(run("create", str(pkg), "--force"))
    result = run("generate", "keystore", str(pkg), "--name", "bad name!")
    fail(result, "not a valid C identifier")


def test_create_and_show_summary(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))

    # Bare `bpak show FILE` triggers the overview via the custom resolver.
    result = run("show", str(pkg))
    ok(result)
    assert "Hash:" in result.output
    assert "Signature:" in result.output
    assert "Payload hash" not in result.output  # the old bogus label is gone

    # The explicit `summary` subcommand is hidden but still dispatchable.
    result = run("show", "summary", str(pkg))
    ok(result)
    assert "Hash:" in result.output


def test_add_and_show_part(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello world")
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))

    result = run("show", "part", str(pkg), "fs")
    ok(result)
    assert "size=" in result.output
    assert "faabeca7" in result.output  # id("fs")

    result = run("show", "part", str(pkg), "fs", "--hash")
    ok(result)
    assert len(result.output.strip()) == 64  # sha256 hex


def test_add_meta_variants(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))

    ok(run("add", "meta", str(pkg), "version", "--from-string", "1.0.0"))
    ok(run("add", "meta", str(pkg), "build-id", "--from-string", "42",
           "--encoder", "integer"))

    # mutual exclusion
    fail(run("add", "meta", str(pkg), "x"),
         "one of --from-string, --from-file is required")

    fail(run("add", "meta", str(pkg), "x",
             "--from-string", "1", "--from-file", str(pkg)),
         "only one of --from-string, --from-file is allowed")


def test_set_meta_updates_value(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "meta", str(pkg), "version", "--from-string", "1.0.0"))
    ok(run("set", "meta", str(pkg), "version", "2.0.0-longer"))

    result = run("extract", "meta", str(pkg), "version", "-o", str(tmp_path / "v.bin"))
    ok(result)
    data = (tmp_path / "v.bin").read_bytes()
    assert data.rstrip(b"\x00").startswith(b"2.0.0-longer")


def test_set_header_requires_at_least_one(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))
    fail(run("set", "header", str(pkg)),
         "at least one of --key-id, --keystore-id is required")
    ok(run("set", "header", str(pkg), "--key-id", "0xdeadbeef"))


def test_set_header_accepts_zero(tmp_path: Path):
    """--key-id 0 is a valid explicit value, not 'missing'."""
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))
    ok(run("set", "header", str(pkg), "--key-id", "0"))
    ok(run("set", "header", str(pkg), "--keystore-id", "0"))


def test_show_meta_part_ref_filter(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello")
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))
    # A global meta (part_ref=0) and a part-scoped one with the same id-name.
    ok(run("add", "meta", str(pkg), "version",
           "--from-string", "global"))
    ok(run("add", "meta", str(pkg), "version",
           "--from-string", "fs-scope", "--part-ref", "fs"))

    all_result = run("show", "meta", str(pkg), "version")
    ok(all_result)
    assert all_result.output.count("\n") >= 2, \
        f"expected both entries listed, got:\n{all_result.output}"

    fs_only = run("show", "meta", str(pkg), "version", "--part-ref", "fs")
    ok(fs_only)
    # part_ref=id('fs')=0xfaabeca7 is printed in the 'ref=' column.
    assert "faabeca7" in fs_only.output
    assert fs_only.output.count("\n") == 1, \
        f"expected 1 entry, got:\n{fs_only.output}"

    global_only = run("show", "meta", str(pkg), "version", "--part-ref", "0")
    ok(global_only)
    assert "faabeca7" not in global_only.output, \
        f"part-scoped entry leaked into part_ref=0 filter:\n{global_only.output}"


def test_delete_part_mutex(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello")
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))

    fail(run("delete", "part", str(pkg)),
         "one of ID, --all is required")
    fail(run("delete", "part", str(pkg), "fs", "--all"),
         "only one of ID, --all is allowed")

    ok(run("delete", "part", str(pkg), "fs"))


def test_delete_meta(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "meta", str(pkg), "version", "--from-string", "1.0.0"))
    ok(run("delete", "meta", str(pkg), "version"))


def test_extract_part_binary_tty_refusal(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello")
    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))

    # CliRunner's stdout isn't a real TTY, so this should succeed.
    result = run("extract", "part", str(pkg), "fs")
    ok(result)

    # Simulate a TTY with a subprocess using `script` so isatty() is true.
    env = os.environ.copy()
    env["PYTHONPATH"] = "../python/"
    proc = subprocess.run(
        ["script", "-qc",
         f"{sys.executable} -m bpak extract part {pkg} fs", "/dev/null"],
        check=False, capture_output=True, env=env,
    )
    combined = proc.stdout.decode("utf-8", errors="replace") + \
        proc.stderr.decode("utf-8", errors="replace")
    assert "refusing to write binary data to a terminal" in combined, combined


def test_compare_flags_same_size_different_content(tmp_path: Path):
    p1 = tmp_path / "a.bpak"
    p2 = tmp_path / "b.bpak"
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"aaaaa\n")
    b.write_bytes(b"bbbbb\n")  # same length as a.bin

    ok(run("create", str(p1), "--force"))
    ok(run("add", "part", str(p1), "fs", "--from", str(a)))

    ok(run("create", str(p2), "--force"))
    ok(run("add", "part", str(p2), "fs", "--from", str(b)))

    result = run("compare", str(p1), str(p2))
    ok(result)
    assert "* faabeca7" in result.output, \
        f"expected content-mismatch marker, got:\n{result.output}"


def test_sign_verify_round_trip(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello")
    priv, pub = _make_keypair(tmp_path)

    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))
    ok(run("add", "meta", str(pkg), "version", "--from-string", "1.0.0"))

    fail(run("sign", str(pkg)), "one of --key, --signature is required")
    ok(run("sign", str(pkg), "--key", str(priv)))

    fail(run("verify", str(pkg)),
         "one of --key, --keystore is required")
    result = run("verify", str(pkg), "--key", str(pub))
    ok(result)
    assert "Verification OK" in result.output


def test_verify_works_on_readonly_file(tmp_path: Path):
    """`bpak verify` must not need write permission on the package."""
    pkg = tmp_path / "a.bpak"
    payload = tmp_path / "data.bin"
    payload.write_bytes(b"hello")
    priv, pub = _make_keypair(tmp_path)

    ok(run("create", str(pkg), "--force"))
    ok(run("add", "part", str(pkg), "fs", "--from", str(payload)))
    ok(run("sign", str(pkg), "--key", str(priv)))

    os.chmod(pkg, 0o444)
    try:
        result = run("verify", str(pkg), "--key", str(pub))
        ok(result)
        assert "Verification OK" in result.output
    finally:
        os.chmod(pkg, 0o644)


def test_transport_round_trip(tmp_path: Path):
    """create -> add part -> transport add -> encode -> decode."""
    pkg = tmp_path / "a.bpak"
    origin = tmp_path / "origin.bpak"
    encoded = tmp_path / "encoded.bpak"
    decoded = tmp_path / "decoded.bpak"
    payload_a = tmp_path / "a.img"
    payload_b = tmp_path / "b.img"
    payload_a.write_bytes(b"A" * 4096)
    payload_b.write_bytes(b"B" * 4096)

    # Build two packages sharing the same part id, used as origin / delta.
    # Transport encoding requires the bpak-package uuid so the two sides
    # can be matched up.
    shared_uuid = "0888b0fa-9c48-4524-9845-06a641b61edd"
    for p, src in ((origin, payload_a), (pkg, payload_b)):
        ok(run("create", str(p), "--force"))
        ok(run("add", "part", str(p), "fs", "--from", str(src)))
        ok(run("add", "meta", str(p), "bpak-package",
               "--from-string", shared_uuid, "--encoder", "uuid"))
        ok(run("transport", "add", str(p), "fs",
               "--encoder", "bsdiff", "--decoder", "bspatch"))

    ok(run("transport", "encode", str(pkg),
           "--output", str(encoded), "--origin", str(origin)))
    assert encoded.exists() and encoded.stat().st_size > 0

    ok(run("transport", "decode", str(encoded),
           "--output", str(decoded), "--origin", str(origin)))
    assert decoded.exists() and decoded.stat().st_size > 0


def test_show_hash_binary_tty_refusal_via_subprocess(tmp_path: Path):
    pkg = tmp_path / "a.bpak"
    ok(run("create", str(pkg), "--force"))
    env = os.environ.copy()
    env["PYTHONPATH"] = "../python/"
    proc = subprocess.run(
        ["script", "-qc",
         f"{sys.executable} -m bpak show hash {pkg} --binary", "/dev/null"],
        check=False, capture_output=True, env=env,
    )
    combined = proc.stdout.decode("utf-8", errors="replace") + \
        proc.stderr.decode("utf-8", errors="replace")
    assert "refusing to write binary data to a terminal" in combined, combined


# --- ad-hoc test runner ---

def _main() -> int:
    failures = []
    import inspect
    import tempfile

    module_globals = globals()
    test_names = sorted(
        name for name, obj in module_globals.items()
        if name.startswith("test_") and inspect.isfunction(obj)
    )

    for name in test_names:
        fn = module_globals[name]
        sig = inspect.signature(fn)
        with tempfile.TemporaryDirectory(prefix="bpak-cli-") as td:
            try:
                if "tmp_path" in sig.parameters:
                    fn(Path(td))
                else:
                    fn()
            except Exception as exc:  # noqa: BLE001
                failures.append((name, exc))
                print(f"FAIL {name}: {exc}")
            else:
                print(f"ok   {name}")

    if failures:
        print(f"\n{len(failures)} / {len(test_names)} tests failed")
        return 1
    print(f"\n{len(test_names)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
