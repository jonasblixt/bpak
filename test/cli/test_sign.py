"""Signing and verification, with the built in signer and with openssl"""

import shutil
import subprocess

import pytest

from bpaktest import (DATA_DIR, DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, Part,
                      corrupt)

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not found")


@pytest.mark.parametrize("hash_kind, signature_kind, sign_key, verify_key", [
    ("sha256", "prime256v1", "secp256r1-key-pair.pem", "secp256r1-pub-key.der"),
    ("sha384", "secp384r1", "secp384r1-key-pair.pem", "secp384r1-pub-key.der"),
    ("sha512", "secp521r1", "secp521r1-key-pair.pem", "secp521r1-pub-key.der"),
    ("sha256", "rsa4096", "dev_rsa_private.pem", "dev_rsa_public.der"),
])
def test_sign_verify(bpak, hash_kind, signature_kind, sign_key, verify_key):
    pkg = bpak.create_package("test.bpak",
                              hash_kind=hash_kind,
                              signature_kind=signature_kind,
                              sign_key=DATA_DIR / sign_key)

    bpak("show", pkg)
    bpak("verify", pkg, "--key", DATA_DIR / verify_key)


def test_verify_wrong_key(bpak):
    pkg = bpak.create_package("test.bpak")

    result = bpak("verify", pkg, "--key", DATA_DIR / "secp384r1-pub-key.der",
                  check=False)
    assert result.returncode != 0


def test_dont_hash(bpak):
    """Parts with the 'dont-hash' flag are not covered by the signature"""
    pkg = bpak.create_package(
        "test.bpak",
        hash_kind="sha256",
        signature_kind="prime256v1",
        parts=[Part("some-data", DATA_DIR / "test_data.bin", dont_hash=True)])
    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)

    # The part data is located directly after the 4 KiB header
    corrupt(pkg, offset=4096)

    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)


def openssl_sign(digest: bytes, key, output) -> None:
    subprocess.run(["openssl", "pkeyutl", "-sign",
                    "-inkey", str(key), "-keyform", "PEM",
                    "-out", str(output)],
                   input=digest, check=True)


@requires_openssl
def test_openssl_sign(bpak, tmp_path):
    """Sign the binary header hash externally and write back the signature"""
    pkg = bpak.create_package(
        "test.bpak",
        hash_kind="sha256",
        signature_kind="prime256v1",
        sign_key=None,
        parts=[Part("data1", DATA_DIR / "diff2_origin.bin", merkle=True),
               Part("data2", DATA_DIR / "diff2_origin.bin")])

    digest = bpak.output("show", pkg, "--binary-hash")
    openssl_sign(digest, DEFAULT_SIGN_KEY, tmp_path / "sig.data")
    bpak("sign", pkg, "--signature", tmp_path / "sig.data")

    bpak("show", pkg)
    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)


@requires_openssl
def test_openssl_resign(bpak, tmp_path):
    """Change key-id and keystore-id of a signed package and re-sign it"""
    pkg = bpak.create_package("test.bpak",
                              hash_kind="sha256",
                              signature_kind="prime256v1")
    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)

    bpak("set", pkg, "--key-id", "the-new-id",
         "--keystore-id", "some-other-keystore")

    digest = bpak.output("show", pkg, "--binary-hash")
    openssl_sign(digest, DEFAULT_SIGN_KEY, tmp_path / "sig.data")
    bpak("sign", pkg, "--signature", tmp_path / "sig.data")

    bpak("show", pkg)
    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)
