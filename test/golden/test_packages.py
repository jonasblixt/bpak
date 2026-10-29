"""Golden sample packages

Every directory next to this file holds packages, patches and keystores
that were created by a released version of bpak, see generate.py. All
versions of bpak must be able to read, verify and decode them, and must
create byte identical packages and patches from the same commands and
inputs. A failure here means that a change breaks compatibility with
packages that already exist. Never change or regenerate a golden set to
make these tests pass.
"""

import hashlib
import json
import shlex
import shutil
from pathlib import Path

import pytest

from bpaktest import (HEADER_SIZE, METADATA_OFFSET, SIGNATURE_OFFSET, Header,
                      bpak_id)

GOLDEN_DIR = Path(__file__).parent
GOLDEN_SETS = sorted(path.parent for path in GOLDEN_DIR.glob("*/manifest.json"))

MERKLE_META = {bpak_id("merkle-salt"), bpak_id("merkle-root-hash")}


def manifest(golden_set: Path) -> dict:
    return json.loads((golden_set / "manifest.json").read_text())


def items(kind: str, only_reproducible: bool = False):
    return [pytest.param(golden_set, name, info,
                         id=f"{golden_set.name}/{name}")
            for golden_set in GOLDEN_SETS
            for name, info in manifest(golden_set)[kind].items()
            if info.get("reproducible", True) or not only_reproducible]


@pytest.fixture
def copy(tmp_path):
    """Copy a golden file into the test directory so that it can not be
    modified by accident"""
    def _copy(golden_set: Path, name: str) -> Path:
        return Path(shutil.copy(golden_set / name, tmp_path / name))
    return _copy


def test_golden_sets_exist():
    assert GOLDEN_SETS, "no golden sets found"


def check_contents(bpak, path: Path, info: dict) -> None:
    """Read every part and every meta data and compare them with the
    manifest"""
    for part in info["parts"]:
        output = bpak.cwd / "part.bin"
        bpak("extract", path, "--part", part["id"], "--output", output)
        assert hashlib.sha256(output.read_bytes()).hexdigest() == \
            part["sha256"], f"part {part['id']}"

    for meta in info["meta"]:
        output = bpak.cwd / "meta.bin"
        bpak("extract", path, "--meta", meta["id"],
             "--part-ref", meta["part_id_ref"], "--output", output)
        assert output.read_bytes().hex() == meta["data"], \
            f"meta {meta['id']}/{meta['part_id_ref']}"


@pytest.mark.parametrize("golden_set, name, info",
                         items("packages") + items("patches"))
def test_read(bpak, copy, golden_set, name, info):
    pkg = copy(golden_set, name)

    bpak("show", pkg)
    check_contents(bpak, pkg, info)


@pytest.mark.parametrize("golden_set, name, info", items("packages"))
def test_verify(bpak, copy, golden_set, name, info):
    pkg = copy(golden_set, name)
    keystore = copy(golden_set, info["keystore"])

    bpak("verify", pkg, "--key", golden_set / "inputs" / info["verify_key"])
    bpak("verify", pkg, "--keystore", keystore)


def comparable(path: Path) -> bytes:
    """The contents of a package without the parts that are different
    every time a package is created: the signature, which is randomized,
    and the random merkle salt with everything that is derived from it"""
    data = bytearray(path.read_bytes())
    header = Header(data)

    data[SIGNATURE_OFFSET:HEADER_SIZE] = bytes(HEADER_SIZE - SIGNATURE_OFFSET)

    for meta in header.meta:
        if meta.id in MERKLE_META:
            start = METADATA_OFFSET + meta.offset
            data[start:start + meta.size] = bytes(meta.size)

    tree_ids = {bpak_id("-hash-tree", part.id) for part in header.parts}
    for part in header.parts:
        if part.id in tree_ids:
            start = header.part_offset(part.id)
            data[start:start + part.stored_size] = bytes(part.stored_size)

    return bytes(data)


@pytest.mark.parametrize("golden_set, name, info", items("packages"))
def test_reproduce(bpak, golden_set, name, info):
    """Packages created with the current version are identical to the
    golden package"""
    inputs = golden_set / "inputs"

    for command in info["commands"]:
        bpak(*(arg.format(inputs=inputs) for arg in shlex.split(command)))

    assert comparable(bpak.cwd / name) == comparable(golden_set / name)


@pytest.mark.parametrize("golden_set, name, info", items("patches"))
def test_decode_patch(bpak, copy, golden_set, name, info):
    """Patches created by older versions can be applied by the current
    version"""
    patch = copy(golden_set, name)
    origin = copy(golden_set, info["origin"])
    output = bpak.cwd / "output.bpak"

    bpak("transport", patch, "--decode", "--origin", origin,
         "--output", output)

    assert output.read_bytes() == (golden_set / info["target"]).read_bytes()


@pytest.mark.parametrize("golden_set, name, info",
                         items("patches", only_reproducible=True))
def test_encode_patch(bpak, copy, golden_set, name, info):
    """The current version creates the same patches as older versions, so
    that devices that run an old version of bpak can apply them"""
    target = copy(golden_set, info["target"])
    origin = copy(golden_set, info["origin"])
    output = bpak.cwd / "output.bpak"

    bpak("transport", target, "--encode", "--origin", origin,
         "--output", output)

    assert output.read_bytes() == (golden_set / name).read_bytes()


# The python package uses the library directly instead of through the tool

@pytest.mark.parametrize("golden_set, name, info",
                         items("packages") + items("patches"))
def test_python_read(pybpak, copy, golden_set, name, info):
    with pybpak.Package(copy(golden_set, name), "rb") as pkg:
        parts = [{"id": f"{part.id:#010x}",
                  "size": part.installed_size,
                  "flags": part.flags,
                  "sha256": hashlib.sha256(part.read_data()).hexdigest()}
                 for part in pkg.parts]
        meta = [{"id": f"{meta.id:#010x}",
                 "part_id_ref": f"{meta.part_id_ref:#010x}",
                 "data": meta.raw_data.hex()}
                for meta in pkg.meta]

    assert parts == info["parts"]
    assert meta == info["meta"]


@pytest.mark.parametrize("golden_set, name, info", items("packages"))
def test_python_verify(pybpak, copy, golden_set, name, info):
    pkg_path = copy(golden_set, name)
    keystore = copy(golden_set, info["keystore"])

    with pybpak.Package(pkg_path, "rb") as pkg:
        assert pkg.verify(golden_set / "inputs" / info["verify_key"])
        assert pkg.verify(keystore_path=keystore)


@pytest.mark.parametrize("golden_set, name, info", items("patches"))
def test_python_decode_patch(pybpak, copy, tmp_path, golden_set, name, info):
    output = tmp_path / "output.bpak"

    with pybpak.Package(copy(golden_set, name), "rb+") as patch, \
            pybpak.Package(copy(golden_set, info["origin"]), "rb+") as origin, \
            pybpak.Package(output, "wb+") as output_pkg:
        pybpak.transport_decode(patch, output_pkg, origin)

    assert output.read_bytes() == (golden_set / info["target"]).read_bytes()


@pytest.mark.parametrize("golden_set, name, info",
                         items("patches", only_reproducible=True))
def test_python_encode_patch(pybpak, copy, tmp_path, golden_set, name, info):
    output = tmp_path / "output.bpak"

    with pybpak.Package(copy(golden_set, info["target"]), "rb+") as target, \
            pybpak.Package(copy(golden_set, info["origin"]), "rb+") as origin, \
            pybpak.Package(output, "wb+") as output_pkg:
        pybpak.transport_encode(target, output_pkg, origin)

    assert output.read_bytes() == (golden_set / name).read_bytes()
