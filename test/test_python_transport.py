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

with bpak.Package("test_python_transport_A.bpak", "rb+") as origin_pkg, \
     bpak.Package("test_python_transport_B.bpak", "rb+") as target_pkg, \
     bpak.Package("test_python_transport_patch.bpak", "wb+") as patch_pkg:

    print("Origin pkg: " + str(origin_pkg))
    print("Target pkg: " + str(target_pkg))
    print("Patch pkg: " + str(patch_pkg))

    bpak.transport_encode(target_pkg, patch_pkg, origin_pkg)
