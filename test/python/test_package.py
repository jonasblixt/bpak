import sys
import uuid

import pytest

from bpaktest import (DATA_DIR, DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, PKG_UUID,
                      BpakError, bpak_id, hash_tree_id)

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


def test_exceptions(pybpak):
    """Every error code has an exception class derived from bpak.Error"""
    exceptions = [getattr(pybpak, name) for name in dir(pybpak)
                  if isinstance(getattr(pybpak, name), type) and
                  issubclass(getattr(pybpak, name), pybpak.Error) and
                  getattr(pybpak, name) is not pybpak.Error]

    assert sorted(e.code for e in exceptions) == sorted(BpakError)


@pytest.mark.parametrize("content, error", [
    (b"Not a package\n", BpakError.READ_ERROR),
    (bytes(8192), BpakError.BAD_MAGIC),
], ids=["short-file", "zeros"])
def test_open_not_a_package(pybpak, tmp_path, content, error):
    path = tmp_path / "file"
    path.write_bytes(content)

    with pytest.raises(pybpak.Error) as e:
        pybpak.Package(path, "rb")

    assert e.value.code == error


def test_non_ascii_path(pybpak, bpak, tmp_path):
    path = tmp_path / "påket.bpak"
    create_package_with_parts(pybpak, path)

    bpak("verify", path, "--key", DEFAULT_VERIFY_KEY)


def test_part_fields(pybpak, tmp_path):
    path = tmp_path / "test.bpak"

    with pybpak.Package(path, "wb+") as p:
        kernel = p.add_file("kernel", KERNEL,
                            flags=pybpak.FLAG_EXCLUDE_FROM_HASH)
        fs = p.add_file("fs", FS)

        assert kernel.installed_size == KERNEL.stat().st_size
        assert kernel.flags == pybpak.FLAG_EXCLUDE_FROM_HASH
        assert kernel.transport_size == 0
        assert (kernel.installed_size + kernel.pad_bytes) % 512 == 0
        assert kernel.size == kernel.installed_size + kernel.pad_bytes
        assert fs.flags == 0
        assert fs.offset == 4096 + kernel.size


@pytest.mark.parametrize("remove_meta", [True, False])
def test_delete_part_meta(pybpak, tmp_path, remove_meta):
    path = tmp_path / "test.bpak"

    with pybpak.Package(path, "wb+") as p:
        p.add_file("kernel", KERNEL)
        p.add_meta(pybpak.id("pb-load-addr"), bpak_id("kernel"),
                   data=bytes(8))

        p.delete_part(bpak_id("kernel"), remove_meta=remove_meta)

        assert p.parts == []
        assert len(p.meta) == (0 if remove_meta else 1)


def test_list_references(pybpak, tmp_path):
    """Listing the parts and meta data does not leak references to them or
    to the package"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(path, "rb") as p:
        before = sys.getrefcount(p)
        # Every part and meta data object holds a reference to the package
        for _ in range(10):
            assert len(p.parts) == 4
            assert len(p.meta) > 0
        assert sys.getrefcount(p) == before


def test_signature_too_large(pybpak, tmp_path):
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        with pytest.raises(pybpak.SizeError):
            p.signature = bytes(pybpak.SIGNATURE_MAX_BYTES + 1)

        p.signature = bytes(pybpak.SIGNATURE_MAX_BYTES)


def test_update_hash(pybpak, tmp_path):
    """update_hash computes the payload hash and returns the header hash,
    the digest that gets signed"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(path, "rb") as p:
        payload_hash = p.payload_hash
        assert len(payload_hash) == 32
        assert p.update_hash() == p.digest
        assert p.payload_hash == payload_hash
