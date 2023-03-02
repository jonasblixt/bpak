#!/usr/bin/env python3
import sys
import os
import uuid

srcdir = sys.argv[1] + "/test"
sys.path.insert(0, "../python/")
import bpak

def log_callback(level, message):
    print("LOG: %i, %s"%(level, message), end='')

bpak.set_log_func(log_callback)

# Call prepare script
assert os.system(f"{srcdir}/test_python_lib_prepare.sh {srcdir}") == 0

id_package = bpak.id("bpak-package")

with bpak.Package("test_python_lib.bpak", "r") as p:
    package_id_meta = p.get_meta(id=id_package)
    assert package_id_meta
    package_id = package_id_meta.as_uuid()
    print(f"Loaded package: {package_id}")

    assert package_id == uuid.UUID("0888b0fa-9c48-4524-9845-06a641b61edd")
    assert bpak.id("bpak-test") == 0x515dcadf

    print("Pkg: " + str(p))

    # Test verify
    assert p.verify(f"{srcdir}/secp256r1-pub-key.pem")

print("Setting new key-id and keystore-id")

# Update key, keystore and re-sign package
with bpak.Package("test_python_lib.bpak", "rb+") as p:
    p.key_id = bpak.id("test-key-id")
    p.keystore_id = bpak.id("test-keystore-id")

    print("Signing:")
    assert p.sign(f"{srcdir}/secp256r1-key-pair.pem")

print("Verify:")
with bpak.Package("test_python_lib.bpak", "r") as p:
    # Check signature again
    assert p.verify(f"{srcdir}/secp256r1-pub-key.pem")


# # Re-sign with another key
print("Setting new key-id and keystore-id")
# Update key, keystore and re-sign package
with bpak.Package("test_python_lib.bpak", "r+") as p:
    p.key_id = bpak.id("test-key-id")
    p.keystore_id = bpak.id("test-keystore-id")

    print("Signing ec384:")
    assert p.sign(f"{srcdir}/secp384r1-key-pair.pem")

print("Verify ec384:")
# # Check signature again
with bpak.Package("test_python_lib.bpak", "r") as p:
    # Check signature again
    assert p.verify(f"{srcdir}/secp384r1-pub-key.pem")

assert os.system(f"../src/bpak verify test_python_lib.bpak --key {srcdir}/secp384r1-pub-key.pem") == 0

print("Test end")
