#!/usr/bin/env python3
import sys
import os
srcdir = os.environ['srcdir']
sys.path.insert(0, "../python/.libs")
sys.path.insert(0, srcdir + "/../python")
import bpak
import bpak.utils
from bpak.package import Package

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.utils.set_log_function(log_callback)

p = Package("test_python_meta.bpak", "r+")
print("Loaded package: " + str(p.id()))
assert str(p.id()) == "0888b0fa-9c48-4524-9845-06a641b61edd"
print("merkle-root-hash: " + p.read_hex_meta(bpak.utils.id("merkle-root-hash")))

# Test package version meta
print("Package version: \"" + p.read_string_meta(bpak.utils.id("bpak-version")) + "\"")
assert p.read_string_meta(bpak.utils.id("bpak-version")) == u"1.0.0"

# Add new meta data
p.write_string_meta(bpak.utils.id('py-test'), "Hello Python")
print("py-test meta: \"%s\""%(p.read_string_meta(bpak.utils.id("py-test"))))
assert p.read_string_meta(bpak.utils.id("py-test")) == u"Hello Python"

# Update meta data
p.write_string_meta(bpak.utils.id('bpak-version'), "1.0.1")
print("Package version: \"" + p.read_string_meta(bpak.utils.id("bpak-version")) + "\"")
assert p.read_string_meta(bpak.utils.id("bpak-version")) == u"1.0.1"

