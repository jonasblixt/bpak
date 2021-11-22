#!/usr/bin/env python3
import sys
import os
srcdir = os.environ['srcdir']
sys.path.insert(0, "../python/.libs")
sys.path.insert(0, srcdir + "/../python")
from bpak.package import Package
from bpak import utils

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

utils.set_log_function(log_callback)

from_pkg = Package("test_python_transport_A.bpak", "rb+")
print("From pkg: " + str(from_pkg))

to_pkg = Package("test_python_transport_B.bpak", "rb+")
print("To pkg: " + str(to_pkg))

patch_pkg = Package("test_python_transport_patch.bpak", "wb+")

to_pkg.transport(from_pkg, patch_pkg)
