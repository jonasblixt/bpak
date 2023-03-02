#!/usr/bin/env python3
import sys
import os
import binascii
import uuid

srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_func(log_callback)

# Call prepare script
assert os.system(f"{srcdir}/test_python_meta_prepare.sh {srcdir}") == 0

id_package = bpak.id("bpak-package")

with bpak.Package("test_python_meta.bpak", "rb+") as p:
    package_id_meta = p.get_meta(id=id_package)
    assert package_id_meta
    package_id = package_id_meta.as_uuid()
    print(f"Loaded package: {package_id}")

    assert package_id == uuid.UUID("0888b0fa-9c48-4524-9845-06a641b61edd")

    merkle_root_hash = p.get_meta(bpak.id('merkle-root-hash'), bpak.id('fs')).raw_data

    print("merkle-root-hash: " + binascii.hexlify(merkle_root_hash).decode())

    # Test package version meta
    bpak_version_meta = p.get_meta(bpak.id("bpak-version"))
    print(f"Package version: \"{bpak_version_meta.as_string()}\"")
    assert bpak_version_meta.as_string() == "1.0.0"

    # Add new meta data
    p.add_meta(id=bpak.id('py-test'), data="Hello Python")
    new_meta = p.get_meta(id=bpak.id('py-test'))
    print(f"py-test meta: \"{new_meta.as_string()}\"")
    assert new_meta.as_string() == "Hello Python"

    # Update meta data
    bpak_version_meta = p.get_meta(bpak.id("bpak-version"))
    bpak_version_meta.raw_data = "1.0.1"

    bpak_version_meta = p.get_meta(bpak.id("bpak-version"))
    print(f"Package version: \"{bpak_version_meta.as_string()}\"")
    assert bpak_version_meta.as_string() == "1.0.1"
