"""Functions exported by the shared library

libbpak.symbols lists every function that libbpak exports. Removing or
renaming one of them breaks programs that are linked against an older
version of the library. New functions must be added to the list.
"""

import ctypes
import shutil
import subprocess
from pathlib import Path

import pytest

SYMBOLS_FILE = Path(__file__).parent / "libbpak.symbols"


def golden_symbols() -> list:
    lines = SYMBOLS_FILE.read_text().splitlines()
    return [line for line in lines if line and not line.startswith("#")]


@pytest.fixture(scope="module")
def libbpak(bpak_build_dir) -> Path:
    path = bpak_build_dir / "lib" / "libbpak.so"
    if not path.exists():
        pytest.fail(f"{path} not found")
    return path


def test_symbols_are_exported(libbpak):
    lib = ctypes.CDLL(str(libbpak))
    missing = [name for name in golden_symbols() if not hasattr(lib, name)]
    assert not missing, f"no longer exported: {missing}"


@pytest.mark.skipif(shutil.which("nm") is None, reason="nm not found")
def test_new_symbols_are_listed(libbpak):
    output = subprocess.run(["nm", "-D", "--defined-only", str(libbpak)],
                            check=True, capture_output=True,
                            text=True).stdout
    exported = {line.split()[-1] for line in output.splitlines()}
    exported = {name for name in exported if name.startswith("bpak_")}

    unlisted = sorted(exported - set(golden_symbols()))
    assert not unlisted, f"add new symbols to {SYMBOLS_FILE}: {unlisted}"
