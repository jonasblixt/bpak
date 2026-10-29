import gc
import uuid

import pytest

from bpaktest import PKG_UUID


def test_meta(pybpak, bpak, origin_pkg):
    bpak("add", origin_pkg, "--meta", "bpak-version", "--from-string", "1.0.0")

    with pybpak.Package(str(origin_pkg), "rb+") as p:
        package_id = p.get_meta(id=pybpak.id("bpak-package")).as_uuid()
        assert package_id == uuid.UUID(PKG_UUID)

        root_hash = p.get_meta(pybpak.id("merkle-root-hash"),
                               pybpak.id("fs")).raw_data
        assert len(root_hash) == 32

        assert p.get_meta(pybpak.id("bpak-version")).as_string() == "1.0.0"

        # Add new meta data
        p.add_meta(id=pybpak.id("py-test"), data="Hello Python")
        assert p.get_meta(id=pybpak.id("py-test")).as_string() == \
            "Hello Python"

        # Update meta data
        p.get_meta(pybpak.id("bpak-version")).raw_data = "1.0.1"
        assert p.get_meta(pybpak.id("bpak-version")).as_string() == "1.0.1"

    # Changes are persisted
    with pybpak.Package(str(origin_pkg), "r") as p:
        assert p.get_meta(id=pybpak.id("py-test")).as_string() == \
            "Hello Python"
        assert p.get_meta(pybpak.id("bpak-version")).as_string() == "1.0.1"


def test_describe(pybpak, origin_pkg):
    with pybpak.Package(origin_pkg, "rb+") as p:
        assert p.get_meta(pybpak.id("bpak-package")).describe() == PKG_UUID
        root_hash = p.get_meta(pybpak.id("merkle-root-hash"), pybpak.id("fs"))
        assert root_hash.describe() == root_hash.raw_data.hex()

        # Meta data that is not well known has no description
        p.add_meta(pybpak.id("py-test"), data="Hello")
        assert p.get_meta(pybpak.id("py-test")).describe() == ""


def test_grow_meta(pybpak, tmp_path):
    """Meta data grows when it is set to longer data, and is kept as it is
    when there is no space left"""
    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        first = p.add_meta(pybpak.id("first"), data="1")
        second = p.add_meta(pybpak.id("second"), data="2")

        first.raw_data = "one"
        assert first.as_string() == "one"
        assert second.as_string() == "2"

        # Use up the rest of the meta data area, meta data is 8 byte aligned
        used = sum((m.size + 7) // 8 * 8 for m in p.meta)
        p.add_meta(pybpak.id("filler"), size=pybpak.METADATA_BYTES - used)

        with pytest.raises(pybpak.NoSpaceLeftError):
            first.raw_data = "one more"
        assert first.as_string() == "one"


def test_meta_too_large(pybpak, tmp_path):
    """Meta data larger than the meta data area is rejected. Sizes above
    65535 were truncated and the data was copied past the header."""
    too_large = 0x10000 + 8

    with pybpak.Package(tmp_path / "test.bpak", "wb+") as p:
        meta = p.add_meta(pybpak.id("first"), data=bytes(8))

        with pytest.raises(pybpak.SizeError):
            meta.raw_data = bytes(too_large)
        with pytest.raises(pybpak.SizeError):
            meta.raw_data = "x" * pybpak.METADATA_BYTES
        assert meta.raw_data == bytes(8)

        with pytest.raises(pybpak.SizeError):
            p.add_meta(pybpak.id("second"), data=bytes(too_large))
        with pytest.raises(pybpak.SizeError):
            p.add_meta(pybpak.id("second"), size=too_large)
        with pytest.raises(pybpak.SizeError):
            p.add_meta(pybpak.id("second"), data="x" * pybpak.METADATA_BYTES)
        assert len(p.meta) == 1

        meta.raw_data = bytes(pybpak.METADATA_BYTES)
        assert meta.size == pybpak.METADATA_BYTES


def test_add_meta_read_only(pybpak, origin_pkg):
    """Adding meta data fails when the header can not be written. This
    released the string data twice and corrupted the heap."""
    for _ in range(100):
        with pybpak.Package(origin_pkg, "rb") as p:
            with pytest.raises(OSError):
                p.add_meta(pybpak.id("py-test"), data="Hello")
        gc.collect()
