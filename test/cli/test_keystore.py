"""C code generation for keystores"""

import os
import shlex
import subprocess

from bpaktest import DATA_DIR, SOURCE_DIR


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
