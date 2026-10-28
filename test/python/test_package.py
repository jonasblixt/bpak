import uuid

import pytest

from bpaktest import (DATA_DIR, DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, PKG_UUID,
                      bpak_id, hash_tree_id)

KERNEL = DATA_DIR / "diff3_origin.bin"
# Merkle trees need a multiple of 4 KiB
FS = DATA_DIR / "diff2_origin.bin"
KEY = DATA_DIR / "secp384r1-pub-key.der"


def test_create_package(pybpak, tmp_path):
    path = str(tmp_path / "test.bpak")

    with pybpak.Package(path, "w") as p:
        p.hash_kind = pybpak.HASH_SHA256
        p.signature_kind = pybpak.SIGN_PRIME256v1
        p.key_id = pybpak.id("test-key-id")
        p.keystore_id = pybpak.id("test-keystore-id")
        p.add_meta(pybpak.id("bpak-version"), data="1.0.1")

        assert p.get_meta(pybpak.id("bpak-version")).as_string() == "1.0.1"

    with pybpak.Package(path, "r") as p:
        assert p.hash_kind == pybpak.HASH_SHA256
        assert p.signature_kind == pybpak.SIGN_PRIME256v1
        assert p.key_id == pybpak.id("test-key-id")
        assert p.keystore_id == pybpak.id("test-keystore-id")
        assert p.get_meta(pybpak.id("bpak-version")).as_string() == "1.0.1"


def test_id(pybpak):
    assert pybpak.id("bpak-test") == 0x515dcadf


def create_package_with_parts(pybpak, path):
    with pybpak.Package(str(path), "wb+") as p:
        p.add_meta(pybpak.id("bpak-package"), data=uuid.UUID(PKG_UUID).bytes)
        p.add_file("kernel", str(KERNEL))
        p.add_file("fs", str(FS), with_merkle_tree=True)
        p.add_key("key", str(KEY))
        p.sign(str(DEFAULT_SIGN_KEY))


def test_parts(pybpak, bpak, tmp_path):
    """Packages created with the python wrapper verify with the tool, and
    the parts read back are the files that were added"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    bpak("verify", path, "--key", DEFAULT_VERIFY_KEY)

    with pybpak.Package(str(path), "rb") as p:
        assert [part.id for part in p.parts] == [
            bpak_id("kernel"), bpak_id("fs"), hash_tree_id("fs"),
            bpak_id("key")]
        assert p.get_part(bpak_id("kernel")).read_data() == \
            KERNEL.read_bytes()
        assert p.get_part(bpak_id("fs")).read_data() == FS.read_bytes()
        assert p.get_part(bpak_id("key")).read_data() == KEY.read_bytes()
        assert p.verify(str(DEFAULT_VERIFY_KEY))


def test_delete_part(pybpak, bpak, tmp_path):
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(str(path), "rb+") as p:
        p.get_part(bpak_id("kernel")).delete()
        p.sign(str(DEFAULT_SIGN_KEY))

    bpak("verify", path, "--key", DEFAULT_VERIFY_KEY)

    with pybpak.Package(str(path), "rb") as p:
        assert bpak_id("kernel") not in [part.id for part in p.parts]
        assert p.get_part(bpak_id("fs")).read_data() == FS.read_bytes()

        with pytest.raises(KeyError):
            p.get_part(bpak_id("kernel"))


def test_verify_fails(pybpak, tmp_path):
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(str(path), "rb") as p:
        with pytest.raises(pybpak.Error):
            p.verify(str(DATA_DIR / "secp384r1-pub-key.der"))


@pytest.mark.parametrize("content", [b"Not a package\n", bytes(8192)],
                         ids=["short-file", "zeros"])
def test_open_not_a_package(pybpak, tmp_path, content):
    """A failed open closed the file a second time and crashed"""
    path = tmp_path / "file"
    path.write_bytes(content)

    with pytest.raises(pybpak.Error):
        pybpak.Package(str(path), "rb")
