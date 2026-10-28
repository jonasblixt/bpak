import os
from pathlib import Path

import pytest

from bpaktest import DATA_DIR, Bpak


def pytest_addoption(parser):
    parser.addoption(
        "--bpak-build-dir",
        default=os.environ.get("BPAK_BUILD_DIR"),
        type=Path,
        help="CMake build directory with the bpak tool and python wrapper "
             "(default: $BPAK_BUILD_DIR)")


@pytest.fixture(scope="session")
def bpak_build_dir(pytestconfig) -> Path:
    build_dir = pytestconfig.getoption("--bpak-build-dir")
    if build_dir is None:
        pytest.fail("--bpak-build-dir or BPAK_BUILD_DIR must be set")
    return build_dir.resolve()


@pytest.fixture(scope="session")
def bpak_tool(bpak_build_dir) -> Path:
    tool = bpak_build_dir / "src" / "bpak"
    if not tool.is_file():
        pytest.fail(f"bpak tool not found at {tool}")
    return tool


@pytest.fixture
def bpak(bpak_tool, tmp_path) -> Bpak:
    """Runs the bpak tool inside the test's temporary directory"""
    return Bpak(bpak_tool, tmp_path)


@pytest.fixture
def make_data(tmp_path):
    """Create a file of 'size_kib' KiB of test data, returns its path"""

    def _make_data(name: str, size_kib: int) -> Path:
        path = tmp_path / name
        path.write_bytes((DATA_DIR / "test_data.bin").read_bytes() * size_kib)
        return path

    return _make_data
