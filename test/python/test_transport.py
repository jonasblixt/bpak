def test_transport_encode_decode(pybpak, bpak, origin_pkg, target_pkg,
                                 tmp_path):
    patch_path = str(tmp_path / "patch.bpak")
    install_path = tmp_path / "install.bpak"

    with pybpak.Package(str(origin_pkg), "rb") as origin, \
         pybpak.Package(str(target_pkg), "rb") as target, \
         pybpak.Package(patch_path, "wb+") as patch:
        pybpak.transport_encode(target, patch, origin)

    with pybpak.Package(str(origin_pkg), "rb") as origin, \
         pybpak.Package(patch_path, "rb") as patch, \
         pybpak.Package(str(install_path), "wb+") as install:
        pybpak.transport_decode(patch, install, origin)

    bpak("compare", target_pkg, install_path)
    assert install_path.read_bytes() == target_pkg.read_bytes()
