"""Transport encoding (diffing) and decoding (patching) of packages

Each scenario creates an origin and a target package, encodes the target
against the origin into a patch package and then decodes the patch package
again. The decoded package must be identical to the target.
"""

import pytest

from bpaktest import DATA_DIR, Part, Transport


def bsdiff(part):
    return Transport(part, "bsdiff", "bspatch")


def bsdiff_lzma(part):
    return Transport(part, "bsdiff-lzma", "bspatch-lzma")


def merkle_tree(part):
    """The hash tree is dropped from the patch and regenerated on decode"""
    return Transport(f"{part}-hash-tree", "remove-data", "merkle-generate")


# '{}' in part sources is replaced with 'origin' or 'target'
DIFF2 = DATA_DIR / "diff2_{}.bin"
DIFF3 = DATA_DIR / "diff3_{}.bin"
DIFF4 = DATA_DIR / "diff4_{}.bin"

SCENARIOS = {
    "bsdiff": (
        [bsdiff("fs"), merkle_tree("fs")],
        [Part("fs", DIFF2, merkle=True)],
    ),
    "bsdiff-lzma": (
        [bsdiff_lzma("fs"), merkle_tree("fs")],
        [Part("fs", DIFF2, merkle=True)],
    ),
    "multiple-bsdiff": (
        [bsdiff("fs"), merkle_tree("fs"),
         bsdiff("fs2"),
         bsdiff("data"),
         merkle_tree("fs2")],
        [Part("fs", DIFF2, merkle=True),
         Part("fs2", DIFF2, merkle=True),
         Part("data", DIFF3)],
    ),
    "mixed-encoded-and-plain-parts": (
        [bsdiff("p1"), bsdiff("p2")],
        [Part("p1", DIFF2), Part("p2", DIFF2), Part("p3", DIFF4)],
    ),
    "no-transport-encoding": (
        [],
        [Part("data1", DIFF2), Part("data2", DIFF2)],
    ),
}


def create_package(bpak, version, transport, parts):
    return bpak.create_package(
        f"{version}.bpak",
        transport=transport,
        parts=[part.for_version(version) for part in parts])


@pytest.mark.parametrize("transport, parts",
                         SCENARIOS.values(), ids=SCENARIOS.keys())
def test_encode_decode(bpak, transport, parts):
    origin = create_package(bpak, "origin", transport, parts)
    target = create_package(bpak, "target", transport, parts)
    patch = bpak.cwd / "patch.bpak"
    install = bpak.cwd / "install.bpak"

    bpak("transport", target, "--encode", "--origin", origin,
         "--output", patch)
    bpak("transport", patch, "--decode", "--origin", origin,
         "--output", install)

    bpak("compare", target, install)
    bpak("show", patch)
    assert install.read_bytes() == target.read_bytes()

    if transport:
        assert patch.stat().st_size < target.stat().st_size


def test_decode_without_encoding(bpak):
    """A package with transport rules that has not been transport encoded
    passes through the decode step unchanged"""
    transport = [bsdiff("p0"), bsdiff("p1"), bsdiff("p2")]
    parts = [Part("p0", DIFF2), Part("p1", DIFF2), Part("p2", DIFF2)]

    origin = create_package(bpak, "origin", transport, parts)
    target = create_package(bpak, "target", transport, parts)
    install = bpak.cwd / "install.bpak"

    bpak("transport", target, "--decode", "--origin", origin,
         "--output", install)

    bpak("compare", target, install)
    assert install.read_bytes() == target.read_bytes()
