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

p = bpak.Package("vA.bpak", "r")
print("Loaded package: " + p.id())
assert p.id() == "0888b0fa-9c48-4524-9845-06a641b61edd"
assert bpak.id("bpak-test") == 0x515dcadf

print("Pkg: " + str(p))

# Test verify

assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))

p.close()

print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = bpak.Package("vA.bpak", "r+")
p.set_key_id("test-key-id")
p.set_keystore_id("test-keystore-id")
print("Signing:")
p.sign("%s/secp256r1-key-pair.pem"%(srcdir))
p.close()
print("Verify:")
# Check signature again
p = bpak.Package("vA.bpak", "r")
assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))
p.close()

# Re-sign with another key
print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = bpak.Package("vA.bpak", "r+")
p.set_key_id("test-key-id")
p.set_keystore_id("test-keystore-id")
print("Signing:")
p.sign("%s/secp384r1-key-pair.pem"%(srcdir))
p.close()
print("Verify:")
# Check signature again
p = bpak.Package("vA.bpak", "r")
assert p.verify("%s/secp384r1-pub-key.pem"%(srcdir))
assert os.system("../src/bpak verify vA.bpak --key %s/secp384r1-pub-key.pem"%(srcdir)) == 0
p.close()
