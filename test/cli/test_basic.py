"""Basic command line handling: help, version, id generation and inspection"""

import pytest

from bpaktest import (DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, PKG_UUID, SOURCE_DIR,
                      BpakError, Part)


@pytest.mark.parametrize("command", [
    None, "create", "add", "transport", "sign", "verify", "show", "set",
    "generate", "compare",
])
def test_help(bpak, command):
    args = [command] if command else []
    assert bpak.output(*args, "--help")


@pytest.mark.parametrize("args", [[], ["-V"], ["--version"], ["-h"]])
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
