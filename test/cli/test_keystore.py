"""Keystores: packages that carry the public keys used for verification"""

import os
import shlex
import subprocess

import pytest

from bpaktest import DATA_DIR, SOURCE_DIR, Header, bpak_id

KEYSTORE_ID = "pb-internal"

# Key name in the keystore: (hash kind, signature kind, private key,
# public key)
KEYS = {
    "pb-development": ("sha256", "prime256v1", "secp256r1-key-pair.pem",
                       "secp256r1-pub-key.der"),
    "pb-development2": ("sha384", "secp384r1", "secp384r1-key-pair.pem",
                        "secp384r1-pub-key.der"),
    "pb-development3": ("sha512", "secp521r1", "secp521r1-key-pair.pem",
                        "secp521r1-pub-key.der"),
    "pb-development4": ("sha256", "rsa4096", "dev_rsa_private.pem",
                        "dev_rsa_public.der"),
}


@pytest.fixture
def keystore(bpak):
    pkg = "keystore.bpak"
    bpak("create", pkg, "-Y")
    bpak("add", pkg, "--meta", "bpak-package",
         "--from-string", "5df103ef-e774-450b-95c5-1fef51ceec28",
         "--encoder", "uuid")
    bpak("add", pkg, "--meta", "keystore-provider-id",
         "--from-string", KEYSTORE_ID, "--encoder", "id")

    for name, (_, _, _, public_key) in KEYS.items():
        bpak("add", pkg, "--part", name, "--from-file", DATA_DIR / public_key,
             "--encoder", "key")

    bpak("sign", pkg, "--key", DATA_DIR / "secp256r1-key-pair.pem")
    return bpak.cwd / pkg


def test_key_parts(keystore):
    """Keys are stored as DER encoded public keys followed by zero
    padding up to the part alignment"""
    header = Header.read(keystore)
    data = keystore.read_bytes()

    for name, (_, _, _, public_key) in KEYS.items():
        der = (DATA_DIR / public_key).read_bytes()
        part = header.part(bpak_id(name))
        offset = header.part_offset(part.id)

        assert part.size == len(der)
        assert (part.size + part.pad_bytes) % 512 == 0
        assert data[offset:offset + part.size] == der
        assert data[offset + part.size:offset + part.stored_size] == \
            bytes(part.pad_bytes)


def test_generate_keystore(bpak, bpak_build_dir, tmp_path):
    """Generate a keystore from a package with public keys and make sure the
    generated code compiles"""
    pkg = "keystore.bpak"
    bpak("create", pkg, "-Y")
    bpak("add", pkg, "--meta", "bpak-package",
         "--from-string", "5df103ef-e774-450b-95c5-1fef51ceec28",
         "--encoder", "uuid")
    bpak("add", pkg, "--meta", "keystore-provider-id",
         "--from-string", "pb-internal", "--encoder", "id")

    for name, key in [("pb-development", "secp256r1-pub-key.pem"),
                      ("pb-development2", "secp384r1-pub-key.pem"),
                      ("pb-development3", "secp521r1-pub-key.pem")]:
        bpak("add", pkg, "--part", name, "--from-file", DATA_DIR / key,
             "--encoder", "key")

    bpak("set", pkg, "--key-id", "pb-development",
         "--keystore-id", "pb-internal")
    bpak("sign", pkg, "--key", DATA_DIR / "secp256r1-key-pair.pem")
    bpak("show", pkg)

    source = tmp_path / "keystore.c"
    source.write_bytes(
        bpak.output("generate", "keystore", pkg, "--name", "test"))

    cc = shlex.split(os.environ.get("CC", "cc"))
    subprocess.run([*cc, "-c", "-Wall", "-Werror",
                    "-I", str(SOURCE_DIR / "include"),
                    "-I", str(bpak_build_dir / "lib"),
                    "-o", str(tmp_path / "keystore.o"),
                    str(source)],
                   check=True)
