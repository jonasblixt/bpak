#!/usr/bin/env python3
"""Generate a set of golden sample packages with the current version of bpak.

The set is written to test/golden/<version>/ together with its input files
and a manifest that describes how every package was created and what it
contains. test_packages.py checks that all sets can still be read, verified,
decoded and reproduced.

Golden sets are never changed once they are committed. Generate a new set
for every release that adds features to the format, older sets stay as they
are.

    $ test/golden/generate.py --bpak-build-dir build
"""

import argparse
import hashlib
import json
import random
import shlex
import shutil
import sys
from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(GOLDEN_DIR.parent))

from bpaktest import (DATA_DIR, SOURCE_DIR, Bpak, Header,  # noqa: E402
                      hash_tree_id)

PACKAGE_UUID = "0888b0fa-9c48-4524-9845-06a641b61edd"
KEYSTORE_UUID = "5df103ef-e774-450b-95c5-1fef51ceec28"
KEYSTORE_ID = "pb-internal"

KEY_FILES = [
    "secp256r1-key-pair.pem", "secp256r1-pub-key.der",
    "secp384r1-key-pair.pem", "secp384r1-pub-key.der",
    "secp521r1-key-pair.pem", "secp521r1-pub-key.der",
    "dev_rsa_private.pem", "dev_rsa_public.der",
]

# Key name: (hash kind, signature kind, private key, public key)
KEYS = {
    "pb-development": ("sha256", "prime256v1", "secp256r1-key-pair.pem",
                       "secp256r1-pub-key.der"),
    "pb-development-384": ("sha384", "secp384r1", "secp384r1-key-pair.pem",
                           "secp384r1-pub-key.der"),
    "pb-development-521": ("sha512", "secp521r1", "secp521r1-key-pair.pem",
                           "secp521r1-pub-key.der"),
    "pb-development-rsa": ("sha256", "rsa4096", "dev_rsa_private.pem",
                           "dev_rsa_public.der"),
}


def modified(data: bytes, rng: random.Random, size: int) -> bytes:
    """A new version of 'data': some bytes changed, a block inserted and
    the result cut or extended to 'size' bytes"""
    data = bytearray(data)
    for _ in range(len(data) // 1000 + 1):
        offset = rng.randrange(len(data))
        data[offset] = rng.randrange(256)
    offset = rng.randrange(len(data))
    data[offset:offset] = rng.randbytes(len(data) // 20)
    data += rng.randbytes(max(0, size - len(data)))
    return bytes(data[:size])


def create_inputs(inputs: Path) -> None:
    inputs.mkdir()
    for name in KEY_FILES:
        shutil.copy(DATA_DIR / name, inputs / name)

    rng = random.Random(0x42504132)
    files = {}
    # Sizes that are not multiples of the part alignment get padded,
    # merkle trees need multiples of 4 KiB
    files["kernel.bin"] = rng.randbytes(3 * 1024 + 100)
    files["dtb.bin"] = rng.randbytes(200)
    files["fs-origin.bin"] = rng.randbytes(32 * 1024)
    files["fs-target.bin"] = modified(files["fs-origin.bin"], rng, 32 * 1024)
    files["data-origin.bin"] = rng.randbytes(6000)
    files["data-target.bin"] = modified(files["data-origin.bin"], rng, 6500)
    files["boot-origin.bin"] = rng.randbytes(3000)
    files["boot-target.bin"] = modified(files["boot-origin.bin"], rng, 3100)

    for name, data in files.items():
        (inputs / name).write_bytes(data)


def package_commands(name, *, key, meta=(), parts=(), transport=(),
                     key_id=None):
    """bpak commands that create a package. '{inputs}' is replaced with the
    directory of the input files when the commands are run."""
    hash_kind, signature_kind, private_key, _ = KEYS[key]
    commands = [
        ["create", name, "-Y", "--hash-kind", hash_kind,
         "--signature-kind", signature_kind],
    ]

    for meta_name, value, encoder, *part_ref in meta:
        command = ["add", name, "--meta", meta_name, "--from-string", value]
        if encoder:
            command += ["--encoder", encoder]
        if part_ref:
            command += ["--part-ref", part_ref[0]]
        commands.append(command)

    for part, encoder, decoder in transport:
        commands.append(["transport", name, "--add", "--part", part,
                         "--encoder", encoder, "--decoder", decoder])

    for part_name, source, *options in parts:
        commands.append(["add", name, "--part", part_name,
                         "--from-file", "{inputs}/" + source, *options])

    commands.append(["set", name, "--key-id", key_id or key,
                     "--keystore-id", KEYSTORE_ID])
    commands.append(["sign", name, "--key", "{inputs}/" + private_key])
    return commands


MERKLE = ["--set-flag", "dont-hash", "--encoder", "merkle"]
PACKAGE_META = ("bpak-package", PACKAGE_UUID, "uuid")

TRANSPORT = [
    ("fs", "bsdiff", "bspatch"),
    ("fs-hash-tree", "remove-data", "merkle-generate"),
    ("boot", "bsdiff-no-comp", "bspatch-no-comp"),
]
TRANSPORT_LZMA = [
    ("data", "bsdiff-lzma", "bspatch-lzma"),
]


def transport_parts(version):
    return [("fs", f"fs-{version}.bin", *MERKLE),
            ("data", f"data-{version}.bin"),
            ("boot", f"boot-{version}.bin"),
            ("dtb", "dtb.bin")]


PACKAGES = {
    "basic.bpak": dict(
        key="pb-development",
        meta=[PACKAGE_META,
              ("bpak-version", "1.2.3-rc1", None),
              ("pb-load-addr", "0x80000000", "integer", "kernel")],
        parts=[("kernel", "kernel.bin"),
               ("dtb", "dtb.bin", "--set-flag", "dont-hash")]),
    "sha384-secp384r1.bpak": dict(
        key="pb-development-384",
        meta=[PACKAGE_META],
        parts=[("kernel", "kernel.bin")]),
    "sha512-secp521r1.bpak": dict(
        key="pb-development-521",
        meta=[PACKAGE_META],
        parts=[("kernel", "kernel.bin")]),
    "sha256-rsa4096.bpak": dict(
        key="pb-development-rsa",
        meta=[PACKAGE_META],
        parts=[("kernel", "kernel.bin")]),
    "merkle.bpak": dict(
        key="pb-development",
        meta=[PACKAGE_META],
        parts=[("fs", "fs-origin.bin", *MERKLE)]),
    "keystore.bpak": dict(
        key="pb-development",
        meta=[("bpak-package", KEYSTORE_UUID, "uuid"),
              ("keystore-provider-id", KEYSTORE_ID, "id")],
        parts=[(name, public_key, "--encoder", "key")
               for name, (_, _, _, public_key) in KEYS.items()]),
    "origin.bpak": dict(
        key="pb-development",
        meta=[PACKAGE_META, ("bpak-version", "1.0.0", None)],
        transport=TRANSPORT,
        parts=transport_parts("origin")),
    "target.bpak": dict(
        key="pb-development",
        meta=[PACKAGE_META, ("bpak-version", "1.1.0", None)],
        transport=TRANSPORT,
        parts=transport_parts("target")),
    "target-lzma.bpak": dict(
        key="pb-development",
        meta=[PACKAGE_META, ("bpak-version", "1.1.0", None)],
        transport=TRANSPORT_LZMA,
        parts=transport_parts("target")),
}

PATCHES = {
    # The output of LZMA depends on the liblzma version, so a patch can
    # only be reproduced exactly when no part uses LZMA
    "patch.bpak": dict(origin="origin.bpak", target="target.bpak",
                       reproducible=True),
    "patch-lzma.bpak": dict(origin="origin.bpak", target="target-lzma.bpak",
                            reproducible=False),
}


def describe(path: Path) -> dict:
    """The parts and meta data of a package as they are stored in the file"""
    header = Header.read(path)
    data = path.read_bytes()
    parts = []
    for part in header.parts:
        offset = header.part_offset(part.id)
        length = part.transport_size if part.flags & 2 else part.size
        parts.append({
            "id": f"{part.id:#010x}",
            "size": part.size,
            "flags": part.flags,
            "sha256": hashlib.sha256(data[offset:offset + length]).hexdigest(),
        })

    meta = [{"id": f"{m.id:#010x}",
             "part_id_ref": f"{m.part_id_ref:#010x}",
             "data": header.meta_data(m.id, m.part_id_ref).hex()}
            for m in header.meta]

    return {"parts": parts, "meta": meta}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bpak-build-dir", type=Path, required=True)
    args = parser.parse_args()

    version = (SOURCE_DIR / "version.txt").read_text().strip()
    output = GOLDEN_DIR / version

    if output.exists():
        sys.exit(f"{output} exists, golden sets must never be changed")

    output.mkdir()
    inputs = output / "inputs"
    create_inputs(inputs)
    bpak = Bpak(args.bpak_build_dir.resolve() / "src" / "bpak", output)

    manifest = {"version": version, "packages": {}, "patches": {}}

    for name, recipe in PACKAGES.items():
        commands = package_commands(name, **recipe)
        for command in commands:
            bpak(*(arg.format(inputs=inputs) for arg in command),
                 verbose=False)

        _, _, _, public_key = KEYS[recipe["key"]]
        manifest["packages"][name] = {
            "commands": [shlex.join(command) for command in commands],
            "verify_key": public_key,
            "keystore": "keystore.bpak",
            **describe(output / name),
        }

    for name, patch in PATCHES.items():
        bpak("transport", patch["target"], "--encode",
             "--origin", patch["origin"], "--output", name, verbose=False)
        manifest["patches"][name] = {**patch, **describe(output / name)}

    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) +
                                          "\n")
    print(f"Created golden set {output}")


if __name__ == "__main__":
    main()
