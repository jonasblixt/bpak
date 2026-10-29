"""Keystores: packages that carry the public keys used for verification"""

import os
import shlex
import subprocess

from bpaktest import (DATA_DIR, HEADER_SIZE, KEYS, KEYSTORE_ID, SOURCE_DIR,
                      BpakError, bpak_id, corrupt)


def test_verify_with_keystore_wrong_key(bpak, keystore):
    """The package is signed with another key than the key-id refers to"""
    pkg = bpak.create_package("test.bpak",
                              sign_key=DATA_DIR / "secp256r1-key-pair.pem",
                              key_id="pb-development-384",
                              keystore_id=KEYSTORE_ID)

    bpak.fails("verify", pkg, "--keystore", keystore,
               error=BpakError.VERIFY_FAIL)


def test_verify_with_keystore_unknown_key(bpak, keystore):
    pkg = bpak.create_package("test.bpak",
                              key_id="not-in-keystore",
                              keystore_id=KEYSTORE_ID)

    bpak.fails("verify", pkg, "--keystore", keystore,
               error=BpakError.KEY_NOT_FOUND)


def test_verify_with_keystore_corrupted(bpak, keystore):
    """The keystore is not signed, its payload hash is verified"""
    pkg = bpak.create_package("test.bpak",
                              key_id="pb-development",
                              keystore_id=KEYSTORE_ID)
    corrupt(keystore, HEADER_SIZE)

    bpak.fails("verify", pkg, "--keystore", keystore,
               error=BpakError.BAD_PAYLOAD_HASH)


def test_verify_with_keystore_wrong_keystore_id(bpak, keystore):
    pkg = bpak.create_package("test.bpak",
                              key_id="pb-development",
                              keystore_id="some-other-keystore")

    bpak.fails("verify", pkg, "--keystore", keystore,
               error=BpakError.KEYSTORE_ID_MISMATCH)


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
    # The secp384r1 key, 120 bytes, ends a line of 8 bytes
    assert not [line for line in source.read_text().splitlines()
                if line.endswith(" ")]
    main = tmp_path / "main.c"
    main.write_text(GENERATED_KEYSTORE_TEST)
    program = tmp_path / "keystore"

    cc = shlex.split(os.environ.get("CC", "cc"))
    subprocess.run([*cc, "-Wall", "-Werror",
                    "-I", str(SOURCE_DIR / "include"),
                    "-I", str(bpak_build_dir / "include"),
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
