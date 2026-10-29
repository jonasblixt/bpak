import pytest

from bpaktest import Part, bsdiff, merkle_tree


def create_merkle_package(bpak, path, source):
    """Signed package with a bsdiff encoded part that has a merkle tree"""
    return bpak.create_package(
        path,
        transport=[bsdiff("fs"), merkle_tree("fs")],
        parts=[Part("fs", source, merkle=True)])


@pytest.fixture
def origin_pkg(bpak, random_data):
    return create_merkle_package(bpak, "origin.bpak",
                                 str(random_data).format("origin"))


@pytest.fixture
def target_pkg(bpak, random_data):
    return create_merkle_package(bpak, "target.bpak",
                                 str(random_data).format("target"))
