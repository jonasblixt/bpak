import importlib
import sys

import pytest

from bpaktest import DATA_DIR, Part, Transport


@pytest.fixture(scope="session")
def pybpak(bpak_python_path):
    """The bpak python package, from the CMake build or installed"""
    sys.path[:0] = bpak_python_path
    module = importlib.import_module("bpak")
    module.set_log_func(
        lambda level, message: print(f"LOG: {level}, {message}", end=""))
    return module


def create_merkle_package(bpak, path, source):
    """Signed package with a bsdiff encoded part that has a merkle tree"""
    return bpak.create_package(
        path,
        transport=[Transport("fs", "bsdiff", "bspatch"),
                   Transport("fs-hash-tree", "remove-data",
                             "merkle-generate")],
        parts=[Part("fs", source, merkle=True)])


@pytest.fixture
def origin_pkg(bpak):
    return create_merkle_package(bpak, "origin.bpak",
                                 DATA_DIR / "diff2_origin.bin")


@pytest.fixture
def target_pkg(bpak):
    return create_merkle_package(bpak, "target.bpak",
                                 DATA_DIR / "diff2_target.bin")
