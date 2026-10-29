"""Basic command line handling: help, version, id generation and inspection"""

import hashlib
import os
import re
import subprocess
import sys
import uuid

import pytest

from bpaktest import (DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, OTHER_PKG_UUID,
                      PKG_UUID, SOURCE_DIR, BpakError, Part, bpak_id)


@pytest.mark.parametrize("command", [
    None, "create", "add", "transport", "sign", "verify", "show", "set",
    "generate", "compare", "extract", "delete", "completion",
])
def test_help(bpak, command):
    args = [command] if command else []
    assert bpak.output(*args, "--help")


# --version is tested by test_version_matches_version_txt
@pytest.mark.parametrize("args", [[], ["-V"], ["-h"]])
def test_no_action(bpak, args):
    bpak(*args, verbose=False)


def test_version_matches_version_txt(bpak):
    version = (SOURCE_DIR / "version.txt").read_text().strip()
    assert bpak.output("--version").decode().split() == ["BitPacker", version]


def test_generate_id(bpak):
    output = bpak.output("generate", "id", "bpak-test").decode()
    assert output.split()[2] == "0x515dcadf"


def test_create_and_show(bpak, make_data):
    """Create, sign, verify and inspect a package with a merkle tree part"""
    data = make_data("data.bin", 128)
    pkg = bpak.create_package("test.bpak",
                              parts=[Part("fs", data, merkle=True)])

    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)
    bpak("show", pkg)
    bpak("show", pkg, "--part", "fs")
    bpak("show", pkg, "--meta", "bpak-package")

    assert PKG_UUID.encode() in bpak.output("show", pkg)


@pytest.mark.parametrize("command", [
    ["verify", "--key", DEFAULT_VERIFY_KEY],
    ["show"],
    ["add", "--meta", "bpak-version", "--from-string", "1.0.0"],
    ["sign", "--key", DEFAULT_SIGN_KEY],
    ["extract", "--part", "data", "--output", "data.bin"],
    ["delete", "--all"],
    ["transport", "--encode", "--output", "output.bpak"],
], ids=lambda command: command[0])
@pytest.mark.parametrize("content, error", [
    (b"Not a package\n", BpakError.READ_ERROR),
    (bytes(8192), BpakError.BAD_MAGIC),
], ids=["short-file", "zeros"])
def test_not_a_package(bpak, tmp_path, command, content, error):
    """Commands fail on files that are not packages and leave them as they
    are"""
    path = tmp_path / "file"
    path.write_bytes(content)

    bpak.fails(command[0], path, *command[1:], error=error)

    assert path.read_bytes() == content


@pytest.mark.parametrize("args", [
    ["create", "test.bpak", "-Y", "--hash-kind", "md5"],
    ["add", "test.bpak", "--from-string", "1.0.0"],
    ["add", "test.bpak", "--meta", "bpak-version"],
    ["add", "test.bpak", "--part", "fs", "--from-string", "1.0.0"],
    ["delete", "test.bpak"],
    ["extract", "test.bpak"],
    ["sign", "test.bpak"],
    ["verify", "test.bpak"],
    ["transport", "test.bpak"],
    ["transport", "test.bpak", "--encode"],
    ["set", "test.bpak"],
], ids=lambda args: "-".join(args[0:1] + args[2:3]))
def test_usage_error(bpak, args):
    """Commands that are used wrong exit with 2 and leave the package as it
    is"""
    bpak("create", "test.bpak")
    pkg = bpak.cwd / "test.bpak"
    content = pkg.read_bytes()

    assert bpak.run(*args, check=False).returncode == 2
    assert pkg.read_bytes() == content


def test_non_ascii_path(bpak, make_data):
    data = make_data("dåta.bin", 4)
    pkg = bpak.create_package("påket.bpak", parts=[Part("fs", data)])

    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)


def test_non_utf8_path(bpak, make_data):
    """File names that are not UTF-8 are printed as they are"""
    data = make_data("data.bin", 4)
    pkg = bpak.create_package(os.fsdecode(b"\xff.bpak"),
                              parts=[Part("fs", data)])

    name = os.fsencode(pkg)
    assert bpak.output("show", pkg).startswith(b"BPAK File: " + name + b"\n")
    assert b"2: '" + name + b"'\n" in bpak.output("compare", pkg, pkg)


def test_extract_to_stdout(bpak, make_data):
    data = make_data("data.bin", 4)
    pkg = bpak.create_package("test.bpak", parts=[Part("fs", data)])

    assert bpak.output("extract", pkg, "--part", "fs") == data.read_bytes()
    assert bpak.output("extract", pkg, "--meta", "bpak-package") == \
        uuid.UUID(PKG_UUID).bytes


def test_extract_write_error(bpak, make_data):
    """Errors writing the output file exit with BPAK_FAILED like the C
    tool, not with a python traceback"""
    data = make_data("data.bin", 4)
    pkg = bpak.create_package("test.bpak", parts=[Part("fs", data)])

    args = ["extract", pkg, "--meta", "bpak-package", "--output",
            bpak.cwd / "missing" / "out.bin"]
    bpak.fails(*args, error=BpakError.FAILED)
    stderr = bpak.run(*args, check=False).stderr.decode()
    assert stderr.startswith("Error: ")
    assert "Traceback" not in stderr


@pytest.mark.parametrize("args", [["show"], ["extract", "--part", "fs"]])
def test_closed_output_pipe(bpak, make_data, args):
    """Output into a pipe whose reader has exited, like 'bpak show | head',
    exits without an error message"""
    data = make_data("data.bin", 4)
    pkg = bpak.create_package("test.bpak", parts=[Part("fs", data)])

    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    with os.fdopen(write_fd, "wb") as stdout:
        result = subprocess.run(
            [sys.executable, "-m", "bpak", args[0], pkg, *args[1:]],
            cwd=bpak.cwd, env=bpak.env, stdout=stdout, stderr=subprocess.PIPE)

    assert result.returncode == 1
    assert result.stderr == b""


def test_show_part_hash(bpak, make_data):
    data = make_data("data.bin", 4)
    pkg = bpak.create_package("test.bpak", parts=[Part("fs", data)])

    assert bpak.output("show", pkg, "--part-hash", "fs").decode().strip() == \
        hashlib.sha256(data.read_bytes()).hexdigest()


def test_compare(bpak, make_data):
    data = make_data("data.bin", 4)
    first = bpak.create_package(
        "first.bpak", parts=[Part("same", data), Part("removed", data)])
    second = bpak.create_package(
        "second.bpak", parts=[Part("same", data), Part("added", data)],
        package_uuid=OTHER_PKG_UUID)
    bpak("add", second, "--meta", "bpak-version", "--from-string", "1.0.0")

    output = bpak.output("compare", first, second).decode()
    marks = {line.split()[1]: line[0] for line in output.splitlines()
             if re.match(r"[-+=*]   [0-9a-f]{8} ", line)}

    assert marks == {
        f"{bpak_id('bpak-package'):08x}": "*",
        f"{bpak_id('bpak-version'):08x}": "+",
        f"{bpak_id('same'):08x}": "=",
        f"{bpak_id('removed'):08x}": "-",
        f"{bpak_id('added'):08x}": "+",
    }
