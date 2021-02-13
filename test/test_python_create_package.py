#!/usr/bin/env python3
import sys
import os
srcdir = os.environ['srcdir']
sys.path.insert(0, "../python/.libs")
sys.path.insert(0, srcdir + "/../python")
from bpak.package import Package
from bpak import utils
import bpak

p = Package("py_create_package.bpak", "w")
p.set_hash_kind(bpak.BPAK_HASH_SHA256)
p.set_signature_kind(bpak.BPAK_SIGN_PRIME256v1)
p.set_key_id(utils.id('test-key-id'))
p.set_keystore_id(utils.id('test-keystore-id'))
p.write_string_meta(utils.id('bpak-version'), "1.0.1")
print("Package version: \"" + p.read_string_meta(utils.id("bpak-version")) + "\"")

p.close()
