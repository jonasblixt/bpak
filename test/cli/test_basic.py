"""Basic command line handling: help, version, id generation and inspection"""

import pytest

from bpaktest import DEFAULT_VERIFY_KEY, PKG_UUID, Part


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
