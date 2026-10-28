"""Create, sign, transport encode and decode packages with the bpak package.

Usage: python3 package.py <private key> <public key>

Creates two versions of a package with a kernel and a root file system in a
temporary directory, encodes the new version as a patch against the old one
and decodes the patch again.
"""

import os
import pathlib
import sys
import tempfile
import uuid

import bpak

PACKAGE_UUID = uuid.UUID("74a53c6d-3556-49f5-a9cd-481ebf22baab")


def create_package(filename, version, kernel, rootfs, sign_key):
    with bpak.Package(filename, "wb+") as pkg:
        pkg.hash_kind = bpak.HASH_SHA256
        pkg.signature_kind = bpak.SIGN_PRIME256v1

        pkg.add_meta(bpak.id("bpak-package"), data=PACKAGE_UUID.bytes)
        # Strings are stored with a terminating NUL
        pkg.add_meta(bpak.id("bpak-version"), data=version)

        pkg.add_file("kernel", kernel)
        # Adds the parts 'rootfs' and 'rootfs-hash-tree'
        pkg.add_file("rootfs", rootfs, with_merkle_tree=True,
                     flags=bpak.FLAG_EXCLUDE_FROM_HASH)

        pkg.add_transport_meta(bpak.id("rootfs"),
                               bpak.id("bsdiff"), bpak.id("bspatch"))
        pkg.add_transport_meta(bpak.id("rootfs-hash-tree"),
                               bpak.id("remove-data"),
                               bpak.id("merkle-generate"))

        pkg.sign(sign_key)


def main():
    sign_key, verify_key = (os.path.abspath(k) for k in sys.argv[1:3])
    os.chdir(tempfile.mkdtemp())

    kernel = pathlib.Path("kernel.bin")
    kernel.write_bytes(os.urandom(256 * 1024))

    rootfs = bytearray(os.urandom(1024 * 1024))
    pathlib.Path("rootfs-1.0.0.img").write_bytes(rootfs)
    rootfs[4096:8192] = bytes(4096)
    pathlib.Path("rootfs-1.1.0.img").write_bytes(rootfs)

    create_package("demo-1.0.0.bpak", "1.0.0", kernel, "rootfs-1.0.0.img",
                   sign_key)
    create_package("demo-1.1.0.bpak", "1.1.0", kernel, "rootfs-1.1.0.img",
                   sign_key)

    with bpak.Package("demo-1.1.0.bpak", "rb") as pkg:
        pkg.verify(verify_key)
        version = pkg.get_meta(bpak.id("bpak-version")).as_string()
        print(f"demo-1.1.0.bpak: version {version}, {pkg.size} bytes")
        for part in pkg.parts:
            print(f"  part {part.id:08x}: {part.installed_size} bytes")

    with bpak.Package("demo-1.1.0.bpak", "rb") as target, \
         bpak.Package("demo-1.0.0.bpak", "rb") as origin, \
         bpak.Package("demo-patch.bpak", "wb+") as patch:
        bpak.transport_encode(target, patch, origin)

    with bpak.Package("demo-patch.bpak", "rb") as patch:
        print(f"demo-patch.bpak: {patch.size} bytes")

    with bpak.Package("demo-patch.bpak", "rb") as patch, \
         bpak.Package("demo-1.0.0.bpak", "rb") as origin, \
         bpak.Package("demo-decoded.bpak", "wb+") as decoded:
        bpak.transport_decode(patch, decoded, origin)

    with bpak.Package("demo-decoded.bpak", "rb") as pkg:
        pkg.verify(verify_key)
        print("demo-decoded.bpak: verification OK")


if __name__ == "__main__":
    main()
