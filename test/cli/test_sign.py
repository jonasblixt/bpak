"""Signing and verification, with the built in signer and with openssl"""

import shutil
import subprocess

import pytest

from bpaktest import (DATA_DIR, DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY,
                      HEADER_SIZE, SIGNATURE_OFFSET, BpakError, Part, corrupt)

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


@pytest.mark.parametrize("hash_kind, sign_key, digest_size", [
    ("sha256", "secp256r1-key-pair.pem", 32),
    ("sha384", "secp384r1-key-pair.pem", 48),
    ("sha512", "secp521r1-key-pair.pem", 64),
])
def test_show_hash(bpak, hash_kind, sign_key, digest_size):
    """The header hash is what gets signed, 'show' prints it in different
    formats"""
    pkg = bpak.create_package("test.bpak", hash_kind=hash_kind,
                              sign_key=DATA_DIR / sign_key)

    digest = bpak.output("show", pkg, "--binary-hash")
    assert len(digest) == digest_size

    assert bpak.output("show", pkg, "--hash").decode().strip() == digest.hex()
    assert f"Header hash:  {digest.hex()}\n" in bpak.output("show", pkg).decode()


def test_verify_wrong_key(bpak):
    pkg = bpak.create_package("test.bpak")

    result = bpak("verify", pkg, "--key", DATA_DIR / "secp384r1-pub-key.der",
                  check=False)
    assert result.returncode != 0


def test_verify_unsigned(bpak):
    pkg = bpak.create_package("test.bpak", sign_key=None)

    bpak.fails("verify", pkg, "--key", DEFAULT_VERIFY_KEY,
               error=BpakError.VERIFY_FAIL)


def test_verify_signature_from_another_package(bpak):
    """A signature is only valid for the header it was created for"""
    pkg = bpak.create_package("test.bpak")
    other = bpak.create_package(
        "other.bpak", parts=[Part("data", DATA_DIR / "test_data.bin")])

    with open(other, "rb") as f:
        f.seek(SIGNATURE_OFFSET)
        signature = f.read(HEADER_SIZE - SIGNATURE_OFFSET)
    with open(pkg, "r+b") as f:
        f.seek(SIGNATURE_OFFSET)
        f.write(signature)

    bpak.fails("verify", pkg, "--key", DEFAULT_VERIFY_KEY,
               error=BpakError.VERIFY_FAIL)


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
def test_openssl_sign(bpak, make_data, tmp_path):
    """Sign the binary header hash externally and write back the signature"""
    data = make_data("data.bin", 16)
    pkg = bpak.create_package(
        "test.bpak",
        hash_kind="sha256",
        signature_kind="prime256v1",
        sign_key=None,
        parts=[Part("data1", data, merkle=True),
               Part("data2", data)])

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
