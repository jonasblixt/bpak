#!/usr/bin/env python3
import sys
import os

srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_func(log_callback)

# Call prepare script
assert os.system(f"{srcdir}/test_python_lib_prepare.sh {srcdir}") == 0

p = bpak.Package("test_python_lib.bpak", "r")
package_id = p.read_uuid_meta(bpak.id("bpak-package"))
print("Loaded package: " + package_id)
assert package_id == "0888b0fa-9c48-4524-9845-06a641b61edd"
assert bpak.id("bpak-test") == 0x515dcadf

print("Pkg: " + str(p))

# Test verify

assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))
p.close()

print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = bpak.Package("test_python_lib.bpak", "r+")
p.set_key_id(bpak.id("test-key-id"))
p.set_keystore_id(bpak.id("test-keystore-id"))
print("Signing:")
p.sign("%s/secp256r1-key-pair.pem"%(srcdir))
p.close()
print("Verify:")
# Check signature again
p = bpak.Package("test_python_lib.bpak", "r")
assert p.verify("%s/secp256r1-pub-key.pem"%(srcdir))
p.close()

# Re-sign with another key
print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
p = bpak.Package("test_python_lib.bpak", "r+")
p.set_key_id(bpak.id("test-key-id"))
p.set_keystore_id(bpak.id("test-keystore-id"))
print("Signing ec384:")
p.sign("%s/secp384r1-key-pair.pem"%(srcdir))
p.close()
print("Verify ec384:")
# Check signature again
p = bpak.Package("test_python_lib.bpak", "r")
assert p.verify("%s/secp384r1-pub-key.pem"%(srcdir))
assert os.system("../src/bpak verify test_python_lib.bpak --key %s/secp384r1-pub-key.pem"%(srcdir)) == 0
p.close()

print("Test end")
