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
