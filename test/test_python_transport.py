#!/usr/bin/env python3
import sys
import os
srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_func(log_callback)
print(f"srcdir: {srcdir}")
# Call prepare script
assert os.system(f"{srcdir}/test_python_transport_prepare.sh {srcdir}") == 0

from_pkg = bpak.Package("test_python_transport_A.bpak", "rb+")
print("From pkg: " + str(from_pkg))

to_pkg = bpak.Package("test_python_transport_B.bpak", "rb+")
print("To pkg: " + str(to_pkg))

patch_pkg = bpak.Package("test_python_transport_patch.bpak", "wb+")

to_pkg.transport_encode(from_pkg, patch_pkg)
