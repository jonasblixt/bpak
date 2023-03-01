#!/usr/bin/env python3
import sys
import os
srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak


with bpak.Package("py_create_package.bpak", "w") as p:
    p.hash_kind = bpak.HASH_SHA256
    p.signature_kind = bpak.SIGN_PRIME256v1
    p.key_id = bpak.id('test-key-id')
    p.keystore_id = bpak.id('test-keystore-id')

    p.add_meta(bpak.id('bpak-version'), data="1.0.1")

    print(f"Package version: \"{p.get_meta(bpak.id('bpak-version')).as_string()}\"")
