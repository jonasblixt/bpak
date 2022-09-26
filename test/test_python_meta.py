#!/usr/bin/env python3
import sys
import os
import binascii

srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_func(log_callback)

# Call prepare script
assert os.system(f"{srcdir}/test_python_meta_prepare.sh {srcdir}") == 0

p = bpak.Package("test_python_meta.bpak", "r+")
print("Loaded package: " + p.read_uuid_meta(bpak.id("bpak-package")))
assert p.read_uuid_meta(bpak.id('bpak-package')) == "0888b0fa-9c48-4524-9845-06a641b61edd"
merkle_root_hash = p.read_raw_meta(bpak.id('merkle-root-hash'), 0)
print("merkle-root-hash: " + binascii.hexlify(merkle_root_hash).decode())

# Test package version meta
print("Package version: \"" + p.read_string_meta(bpak.id("bpak-version")) + "\"")
assert p.read_string_meta(bpak.id("bpak-version")) == u"1.0.0"

# Add new meta data
p.write_string_meta(bpak.id('py-test'), "Hello Python")
print("py-test meta: \"%s\""%(p.read_string_meta(bpak.id("py-test"))))
assert p.read_string_meta(bpak.id("py-test")) == u"Hello Python"

# Update meta data
p.write_string_meta(bpak.id('bpak-version'), "1.0.1")
print("Package version: \"" + p.read_string_meta(bpak.id("bpak-version")) + "\"")
assert p.read_string_meta(bpak.id("bpak-version")) == u"1.0.1"

