import importlib
import sys

import pytest

from bpaktest import Part, Transport


@pytest.fixture(scope="session")
def pybpak(bpak_python_path):
    """The bpak python package, from the CMake build or installed"""
    sys.path[:0] = bpak_python_path
    module = importlib.import_module("bpak")
    module.set_log_func(print_log)
    return module


def print_log(level, message):
    print(f"LOG: {level}, {message}", end="")


@pytest.fixture
def set_log_func(pybpak):
    """pybpak.set_log_func, restores the default log function after the
    test"""
    yield pybpak.set_log_func
    pybpak.set_log_func(print_log)


def create_merkle_package(bpak, path, source):
    """Signed package with a bsdiff encoded part that has a merkle tree"""
    return bpak.create_package(
        path,
        transport=[Transport("fs", "bsdiff", "bspatch"),
                   Transport("fs-hash-tree", "remove-data",
                             "merkle-generate")],
        parts=[Part("fs", source, merkle=True)])


@pytest.fixture
def origin_pkg(bpak, random_data):
    return create_merkle_package(bpak, "origin.bpak",
                                 str(random_data).format("origin"))


@pytest.fixture
def target_pkg(bpak, random_data):
    return create_merkle_package(bpak, "target.bpak",
                                 str(random_data).format("target"))
