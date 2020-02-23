#!/usr/bin/env python3
import sys
sys.path.append("../python/.libs")

import bpak

p = bpak.Package("vA.bpak", "r")
print("Loaded package: " + p.id())

