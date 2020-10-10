#!/usr/bin/env python3
import sys
sys.path.append("../python/.libs")

import bpak

p = bpak.Package("py_create_package.bpak", "w")
print("Loaded package: " + p.id())

