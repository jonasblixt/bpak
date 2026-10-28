import uuid

from bpaktest import DATA_DIR, PKG_UUID


def test_verify_and_resign(pybpak, bpak, origin_pkg):
    path = str(origin_pkg)

    with pybpak.Package(path, "r") as p:
        package_id = p.get_meta(id=pybpak.id("bpak-package")).as_uuid()
        assert package_id == uuid.UUID(PKG_UUID)
        print(f"Package: {p}")

        assert p.verify(str(DATA_DIR / "secp256r1-pub-key.pem"))

    # Update key-id and keystore-id and re-sign the package
    with pybpak.Package(path, "rb+") as p:
        p.key_id = pybpak.id("test-key-id")
        p.keystore_id = pybpak.id("test-keystore-id")
        assert p.sign(str(DATA_DIR / "secp256r1-key-pair.pem"))

    with pybpak.Package(path, "r") as p:
        assert p.verify(str(DATA_DIR / "secp256r1-pub-key.pem"))

    # Re-sign with another key
    with pybpak.Package(path, "r+") as p:
        assert p.sign(str(DATA_DIR / "secp384r1-key-pair.pem"))

    with pybpak.Package(path, "r") as p:
        assert p.verify(str(DATA_DIR / "secp384r1-pub-key.pem"))

    # The tool must agree with the python wrapper
    bpak("verify", origin_pkg, "--key", DATA_DIR / "secp384r1-pub-key.pem")
