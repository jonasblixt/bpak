#!/usr/bin/env python3
import sys
import os
srcdir = os.environ['srcdir']
sys.path.append("../python/.libs")
sys.path.append(srcdir + "/../python")
import bpak

p = bpak.Package("py_create_package.bpak", "w")
p.set_hash_kind(bpak.BPAK_HASH_SHA256)
p.set_signature_kind(bpak.BPAK_SIGN_PRIME256v1)
p.set_key_id(bpak.id('test-key-id'))
p.set_keystore_id(bpak.id('test-keystore-id'))
p.write_string_meta(bpak.id('bpak-version'), "1.0.1")
print("Package version: \"" + p.read_string_meta(bpak.id("bpak-version")) + "\"")

p.close()
