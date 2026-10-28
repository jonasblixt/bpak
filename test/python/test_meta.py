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


def test_add_meta_read_only(pybpak, origin_pkg):
    """Adding meta data fails when the header can not be written. This
    released the string data twice and corrupted the heap."""
    for _ in range(100):
        with pybpak.Package(str(origin_pkg), "rb") as p:
            with pytest.raises(OSError):
                p.add_meta(pybpak.id("py-test"), data="Hello")
        gc.collect()
