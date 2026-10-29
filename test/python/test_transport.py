def test_transport_decode_headers(pybpak, origin_pkg, target_pkg, tmp_path):
    """Decoding leaves the input package unchanged and the output package
    is the target package"""
    patch_path = str(tmp_path / "patch.bpak")
    install_path = tmp_path / "install.bpak"

    with pybpak.Package(str(origin_pkg), "rb") as origin, \
         pybpak.Package(str(target_pkg), "rb") as target, \
         pybpak.Package(patch_path, "wb+") as patch:
        pybpak.transport_encode(target, patch, origin)

    with pybpak.Package(str(origin_pkg), "rb") as origin, \
         pybpak.Package(str(target_pkg), "rb") as target, \
         pybpak.Package(patch_path, "rb") as patch, \
         pybpak.Package(str(install_path), "wb+") as install:
        patch_size = patch.size
        patch_flags = [part.flags for part in patch.parts]
        assert any(part.is_transport_encoded for part in patch.parts)

        pybpak.transport_decode(patch, install, origin)

        assert patch.size == patch_size
        assert [part.flags for part in patch.parts] == patch_flags
        assert install.size == target.size
        assert [(part.id, part.flags, part.transport_size)
                for part in install.parts] == \
               [(part.id, part.flags, part.transport_size)
                for part in target.parts]

    assert install_path.read_bytes() == target_pkg.read_bytes()
