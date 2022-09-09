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

# Call prepare script
assert os.system("%s/test_python_lib_prepare.sh"%(srcdir)) == 0

p = Package("test_python_lib.bpak", "r")
print("Loaded package: " + str(p.id()))
assert str(p.id()) == "0888b0fa-9c48-4524-9845-06a641b61edd"
assert utils.id("bpak-test") == 0x515dcadf

print("Pkg: " + str(p))

# Test verify

assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))
p.close()

print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = Package("test_python_lib.bpak", "r+")
p.set_key_id(utils.id("test-key-id"))
p.set_keystore_id(utils.id("test-keystore-id"))
print("Signing:")
p.sign("%s/secp256r1-key-pair.pem"%(srcdir))
p.close()
print("Verify:")
# Check signature again
p = Package("test_python_lib.bpak", "r")
assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))
p.close()

# Re-sign with another key
print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = Package("test_python_lib.bpak", "r+")
p.set_key_id(utils.id("test-key-id"))
p.set_keystore_id(utils.id("test-keystore-id"))
print("Signing ec384:")
p.sign("%s/secp384r1-key-pair.pem"%(srcdir))
p.close()
print("Verify ec384:")
# Check signature again
p = Package("test_python_lib.bpak", "r")
assert p.verify("%s/secp384r1-pub-key.pem"%(srcdir))
assert os.system("../src/bpak verify test_python_lib.bpak --key %s/secp384r1-pub-key.pem"%(srcdir)) == 0
p.close()

print("Test end")
