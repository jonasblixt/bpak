import os
from pathlib import Path

import pytest

from bpaktest import DATA_DIR, Bpak, python_path


def pytest_addoption(parser):
    parser.addoption(
        "--bpak-build-dir",
        default=os.environ.get("BPAK_BUILD_DIR"),
        type=Path,
        help="CMake build directory (default: $BPAK_BUILD_DIR). Without it "
             "the tests use the installed bpak package, for example the "
             "editable install of 'uv sync', and skip the tests that need "
             "the CMake build.")


def cmake_build_dir(pytestconfig):
    build_dir = pytestconfig.getoption("--bpak-build-dir")
    if build_dir is None:
        return None

    build_dir = build_dir.resolve()
    if not any((build_dir / "python" / "bpak").glob("_bpak*")):
        pytest.fail(f"the C extension bpak._bpak is not built in {build_dir}")
    return build_dir


@pytest.fixture(scope="session")
def bpak_build_dir(pytestconfig) -> Path:
    """The CMake build directory, tests that use it are skipped without
    --bpak-build-dir"""
    build_dir = cmake_build_dir(pytestconfig)
    if build_dir is None:
        pytest.skip("needs the CMake build, --bpak-build-dir")
    return build_dir


@pytest.fixture(scope="session")
def bpak_python_path(pytestconfig) -> list:
    """Paths to put first on the python path to use the bpak package of the
    CMake build, empty to use the installed package"""
    build_dir = cmake_build_dir(pytestconfig)
    return python_path(build_dir) if build_dir else []


@pytest.fixture
def bpak(bpak_python_path, tmp_path) -> Bpak:
    """Runs the bpak tool inside the test's temporary directory"""
    return Bpak(bpak_python_path, tmp_path)


@pytest.fixture
def make_data(tmp_path):
    """Create a file of 'size_kib' KiB of test data, returns its path"""

    def _make_data(name: str, size_kib: int) -> Path:
        path = tmp_path / name
        path.write_bytes((DATA_DIR / "test_data.bin").read_bytes() * size_kib)
        return path

    return _make_data
