#!/usr/bin/env python3
import sys
import os
srcdir = os.environ['srcdir']
sys.path.append("../python/.libs")
sys.path.append(srcdir + "/../python")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_function(log_callback)

p = bpak.Package("test_python_meta.bpak", "r+")
print("Loaded package: " + str(p.id()))
assert str(p.id()) == "0888b0fa-9c48-4524-9845-06a641b61edd"
print("merkle-root-hash: " + p.read_hex_meta(bpak.id("merkle-root-hash")))

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

