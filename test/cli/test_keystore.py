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


@pytest.mark.parametrize("key_name", KEYS)
def test_verify_with_keystore(bpak, keystore, key_name):
    hash_kind, signature_kind, private_key, _ = KEYS[key_name]
    pkg = bpak.create_package("test.bpak",
                              hash_kind=hash_kind,
                              signature_kind=signature_kind,
                              sign_key=DATA_DIR / private_key,
                              key_id=key_name,
                              keystore_id=KEYSTORE_ID)

    bpak("verify", pkg, "--keystore", keystore)


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


GENERATED_KEYSTORE_TEST = r"""
#include <stdio.h>
#include <bpak/keystore.h>

extern const struct bpak_keystore keystore_test;

int main(void)
{
    printf("%x %u\n", keystore_test.id, keystore_test.no_of_keys);

    for (unsigned int i = 0; i < keystore_test.no_of_keys; i++) {
        const struct bpak_key *k = keystore_test.keys[i];

        printf("%x %u ", k->id, k->kind);
        for (unsigned int n = 0; n < k->size; n++)
            printf("%02x", k->data[n]);
        printf("\n");
    }

    return 0;
}
"""


def test_generate_keystore(bpak, bpak_build_dir, keystore, tmp_path):
    """Generate C code for a keystore, compile it and check that it
    contains the keys from the keystore package"""
    source = tmp_path / "keystore.c"
    source.write_bytes(
        bpak.output("generate", "keystore", keystore, "--name", "test"))
    main = tmp_path / "main.c"
    main.write_text(GENERATED_KEYSTORE_TEST)
    program = tmp_path / "keystore"

    cc = shlex.split(os.environ.get("CC", "cc"))
    subprocess.run([*cc, "-Wall", "-Werror",
                    "-I", str(SOURCE_DIR / "include"),
                    "-I", str(bpak_build_dir / "lib"),
                    "-o", str(program), str(source), str(main)],
                   check=True)

    lines = subprocess.run([str(program)], check=True, capture_output=True,
                           text=True).stdout.splitlines()

    assert lines[0] == f"{bpak_id(KEYSTORE_ID):x} {len(KEYS)}"

    # enum bpak_key_kind
    key_kinds = {"prime256v1": 2, "secp384r1": 3, "secp521r1": 4,
                 "rsa4096": 1}
    expected = [
        f"{bpak_id(name):x} {key_kinds[signature_kind]} "
        f"{(DATA_DIR / public_key).read_bytes().hex()}"
        for name, (_, signature_kind, _, public_key) in KEYS.items()
    ]
    assert lines[1:] == expected
