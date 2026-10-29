import os
import sys
import uuid
from pathlib import Path

import pytest

from bpaktest import (DATA_DIR, DEFAULT_SIGN_KEY, DEFAULT_VERIFY_KEY, PKG_UUID,
                      BpakError, bpak_id, hash_tree_id, random_bytes)

KERNEL = DATA_DIR / "diff3_origin.bin"
# Merkle trees need a multiple of 4 KiB
FS_DATA = random_bytes(64 * 1024)
KEY = DATA_DIR / "secp384r1-pub-key.der"


def write_fs(directory: Path) -> Path:
    path = directory / "fs.bin"
    path.write_bytes(FS_DATA)
    return path


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
        p.add_file("fs", str(write_fs(path.parent)), with_merkle_tree=True)
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
        assert p.get_part(bpak_id("fs")).read_data() == FS_DATA
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
        assert p.get_part(bpak_id("fs")).read_data() == FS_DATA

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


def test_read_empty_part(pybpak, tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        part = p.add_file("empty", empty)

        assert part.installed_size == 0
        assert part.read_data() == b""


def test_log_func_raises(pybpak, set_log_func, origin_pkg, monkeypatch):
    """An exception in the log function is reported as unraisable and the
    library continues, it was left set and surfaced as a SystemError"""
    unraisable = []
    monkeypatch.setattr(sys, "unraisablehook", unraisable.append)

    def log(level, message):
        raise BrokenPipeError

    set_log_func(log)

    with pybpak.Package(origin_pkg, "rb") as p:
        assert len(p.parts) == 2

    assert unraisable
    assert all(isinstance(u.exc_value, BrokenPipeError) for u in unraisable)


def test_log_non_utf8_path(pybpak, set_log_func, tmp_path):
    """Log messages with file names that are not UTF-8 reach the log
    function"""
    path = tmp_path / os.fsdecode(b"\xff.bpak")
    create_package_with_parts(pybpak, path)
    messages = []
    set_log_func(lambda level, message: messages.append(message))

    with pybpak.Package(path, "rb") as p:
        assert len(p.parts) == 4

    assert any("\\xff.bpak" in m for m in messages)


def test_read_truncated_part(pybpak, tmp_path):
    """A part that is cut short reports the end of the file, the message
    was 'Success'"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)
    with pybpak.Package(path, "rb") as p:
        kernel = p.get_part(bpak_id("kernel"))
        end = kernel.offset + kernel.installed_size

    with path.open("rb+") as f:
        f.truncate(end - 1)

    with pybpak.Package(path, "rb") as p:
        with pytest.raises(OSError, match="unexpected end of file"):
            p.get_part(bpak_id("kernel")).read_data()


def test_part_fields(pybpak, tmp_path):
    path = tmp_path / "test.bpak"

    with pybpak.Package(path, "wb+") as p:
        kernel = p.add_file("kernel", KERNEL,
                            flags=pybpak.FLAG_EXCLUDE_FROM_HASH)
        fs = p.add_file("fs", write_fs(tmp_path))

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


def test_closed_package(pybpak, tmp_path):
    """Using a closed package raises ValueError, it dereferenced the closed
    file and crashed"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(path, "rb+") as p:
        part = p.get_part(bpak_id("kernel"))
        meta = p.get_meta(pybpak.id("bpak-package"))

    def set_key_id():
        p.key_id = 1

    def set_signature():
        p.signature = bytes(8)

    def set_raw_data():
        meta.raw_data = bytes(8)

    operations = [
        p.write_header,
        p.update_hash,
        lambda: p.digest,
        set_key_id,
        set_signature,
        lambda: p.add_meta(pybpak.id("py-test"), data="Hello"),
        lambda: p.add_file("test", KERNEL),
        lambda: p.add_key("test", KEY),
        lambda: p.verify(DEFAULT_VERIFY_KEY),
        lambda: p.sign(DEFAULT_SIGN_KEY),
        lambda: p.part_sha256(bpak_id("kernel")),
        lambda: p.extract_file(bpak_id("kernel"), tmp_path / "kernel"),
        lambda: p.delete_part(bpak_id("kernel")),
        p.delete_all_parts,
        part.read_data,
        part.delete,
        set_raw_data,
        meta.delete,
        lambda: pybpak.transport_encode(p, p),
    ]

    for operation in operations:
        with pytest.raises(ValueError, match="closed package"):
            operation()

    # Closing again is fine
    p.close()


def test_signature_too_large(pybpak, tmp_path):
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        with pytest.raises(pybpak.SizeError):
            p.signature = bytes(pybpak.SIGNATURE_MAX_BYTES + 1)

        p.signature = bytes(pybpak.SIGNATURE_MAX_BYTES)


@pytest.mark.parametrize("signature", [bytes(8), None],
                         ids=["set", "clear"])
def test_signature_write_error(pybpak, tmp_path, signature):
    """Setting and clearing the signature report a failed header write, a
    failed clear was ignored"""
    path = tmp_path / "test.bpak"
    create_package_with_parts(pybpak, path)

    with pybpak.Package(path, "rb") as p:
        with pytest.raises(pybpak.WriteError):
            p.signature = signature


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


@pytest.mark.parametrize("name, bits", [("hash_kind", 8),
                                        ("signature_kind", 8),
                                        ("key_id", 32),
                                        ("keystore_id", 32)])
def test_header_field_values(pybpak, tmp_path, name, bits):
    """The header fields reject values that do not fit, they were
    truncated, and deleting them raises TypeError, it crashed"""
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        setattr(p, name, 2**bits - 1)
        assert getattr(p, name) == 2**bits - 1

        for value in (2**bits, 2**bits + 5, 2**64, -1):
            with pytest.raises(OverflowError):
                setattr(p, name, value)
        with pytest.raises(TypeError):
            setattr(p, name, "1")
        with pytest.raises(TypeError, match="cannot delete"):
            delattr(p, name)

        assert getattr(p, name) == 2**bits - 1


def test_part_id_values(pybpak, tmp_path):
    """Part.id rejects values that do not fit and deleting it raises
    TypeError, it crashed"""
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        part = p.add_file("kernel", KERNEL)

        with pytest.raises(OverflowError):
            part.id = 2**32
        with pytest.raises(TypeError, match="cannot delete"):
            del part.id

        assert part.id == bpak_id("kernel")


def test_wrapper_details(pybpak, tmp_path):
    """sign() reported argument errors as verify() and the docstring of
    Package.meta described the parts"""
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        with pytest.raises(TypeError, match=r"sign\(\)"):
            p.sign()

    assert "meta data" in pybpak.Package.meta.__doc__
