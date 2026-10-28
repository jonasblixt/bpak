"""Adding, updating and extracting meta data and part data"""

import os

import pytest

from bpaktest import Part


@pytest.fixture
def pkg(bpak):
    return bpak.create_package("test.bpak",
                               hash_kind="sha256",
                               signature_kind="prime256v1")


def extract_meta(bpak, pkg, name) -> bytes:
    return bpak.output("extract", pkg, "--meta", name)


# Strings are stored with a NUL terminator, integers as 64 bit little endian
# and ids as the 32 bit little endian bpak id of the string.
@pytest.mark.parametrize("encoder, value, expected", [
    pytest.param(None, "hello", b"hello\0", id="string"),
    pytest.param("integer", "0x11223344", bytes.fromhex("4433221100000000"),
                 id="integer"),
    pytest.param("id", "Hello", bytes.fromhex("9f7ef331"), id="id"),
])
def test_add_meta_from_string(bpak, pkg, encoder, value, expected):
    encoder_args = ["--encoder", encoder] if encoder else []
    bpak("add", pkg, "--meta", "test-meta", "--from-string", value,
         *encoder_args)

    assert extract_meta(bpak, pkg, "test-meta") == expected


def test_add_meta_from_file(bpak, pkg, tmp_path):
    data = os.urandom(5)
    (tmp_path / "meta.bin").write_bytes(data)

    bpak("add", pkg, "--meta", "test-meta", "--from-file", "meta.bin")
    bpak("extract", pkg, "--meta", "test-meta", "--output", "dump.bin")

    assert (tmp_path / "dump.bin").read_bytes() == data


@pytest.mark.parametrize("encoder, initial, updated, expected", [
    pytest.param(None, "Hello", "Hello World", b"Hello World\0",
                 id="string"),
    pytest.param("id", "Hello", "World", bytes.fromhex("5ac9943d"), id="id"),
    pytest.param("integer", "0x11223344", "0x55667788",
                 bytes.fromhex("8877665500000000"), id="integer"),
])
def test_set_meta(bpak, pkg, encoder, initial, updated, expected):
    encoder_args = ["--encoder", encoder] if encoder else []
    bpak("add", pkg, "--meta", "test-meta", "--from-string", initial,
         *encoder_args)
    bpak("set", pkg, "--meta", "test-meta", "--from-string", updated,
         *encoder_args)
    bpak("show", pkg)

    assert extract_meta(bpak, pkg, "test-meta") == expected


def test_extract_part(bpak, make_data, tmp_path):
    data = make_data("data.bin", 128)
    pkg = bpak.create_package("test.bpak",
                              parts=[Part("fs", data, merkle=True)])

    bpak("extract", pkg, "--part", "fs", "--output", "dump.bin")

    assert (tmp_path / "dump.bin").read_bytes() == data.read_bytes()
