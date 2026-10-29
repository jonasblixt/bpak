"""The 'delete' command removes parts and their meta data"""

import pytest

from bpaktest import hash_tree_id

# Package hash of an unsigned package with no parts or meta data
EMPTY_PACKAGE_HASH = (
    "7d0bbb3b969c6cef24969b5e23a9de85b855784a64610243f8f0ddd5ed6773d0")


@pytest.fixture
def data1(make_data):
    return make_data("data1.bin", 134)


@pytest.fixture
def data2(make_data):
    return make_data("data2.bin", 76)


def package_hash(bpak, pkg) -> str:
    return bpak.output("show", "-H", pkg).decode().strip()


@pytest.fixture
def pkg_two_parts(bpak, data1, data2):
    """Package with parts test1 and test2"""
    bpak("create", "two_parts.bpak", "-Y")
    bpak("add", "two_parts.bpak", "--part", "test1", "--from-file", data1)
    bpak("add", "two_parts.bpak", "--part", "test2", "--from-file", data2)
    return bpak.cwd / "two_parts.bpak"


@pytest.fixture
def pkg_one_part(bpak, data2):
    """Package with only part test2, the expected result of deleting test1"""
    bpak("create", "one_part.bpak", "-Y")
    bpak("add", "one_part.bpak", "--part", "test2", "--from-file", data2)
    return bpak.cwd / "one_part.bpak"


def add_meta(bpak, pkg, name, value, part_ref=None):
    part_ref_args = ["--part-ref", part_ref] if part_ref else []
    bpak("add", pkg, "--meta", name, *part_ref_args,
         "--from-string", value, "--encoder", "integer")


@pytest.mark.parametrize("args", [
    ["--all"],
    ["--all", "--part", "test1"],
], ids=["all", "all-and-part"])
def test_delete_all(bpak, pkg_two_parts, args):
    """--all deletes all parts, also with --part like the C tool"""
    bpak("delete", pkg_two_parts, *args)

    assert package_hash(bpak, pkg_two_parts) == EMPTY_PACKAGE_HASH


def test_delete_part_with_meta(bpak, pkg_two_parts, pkg_one_part):
    """Meta data that references a deleted part is deleted as well"""
    add_meta(bpak, pkg_two_parts, "meta1", "0x11")
    add_meta(bpak, pkg_two_parts, "part1-meta2", "0x22", part_ref="test1")
    add_meta(bpak, pkg_two_parts, "part2-meta3", "0x33", part_ref="test2")
    add_meta(bpak, pkg_two_parts, "meta4", "0x44")

    add_meta(bpak, pkg_one_part, "meta1", "0x11")
    add_meta(bpak, pkg_one_part, "part2-meta3", "0x33", part_ref="test2")
    add_meta(bpak, pkg_one_part, "meta4", "0x44")

    bpak("delete", pkg_two_parts, "--part", "test1")

    assert package_hash(bpak, pkg_two_parts) == package_hash(bpak,
                                                             pkg_one_part)


def test_delete_parts_from_the_end(bpak, pkg_two_parts):
    bpak("delete", pkg_two_parts, "--part", "test2")
    bpak("delete", pkg_two_parts, "--part", "test1")
    bpak("show", pkg_two_parts)

    assert package_hash(bpak, pkg_two_parts) == EMPTY_PACKAGE_HASH



@pytest.mark.parametrize("keep_meta", [False, True], ids=["meta", "keep-meta"])
def test_delete_part_with_merkle_tree(bpak, make_data, data2, pkg_one_part,
                                      keep_meta):
    """The hash tree of a part added with '--encoder merkle' is deleted with
    the part"""
    bpak("create", "merkle.bpak", "-Y")
    bpak("add", "merkle.bpak", "--part", "test1",
         "--from-file", make_data("merkle.bin", 136), "--encoder", "merkle")
    bpak("add", "merkle.bpak", "--part", "test2", "--from-file", data2)
    pkg = bpak.cwd / "merkle.bpak"
    tree_id = f"{hash_tree_id('test1'):08x}"
    assert tree_id in bpak.output("show", pkg).decode()

    bpak("delete", pkg, "--part", "test1",
         *(["--keep-meta"] if keep_meta else []))

    assert tree_id not in bpak.output("show", pkg).decode()
    if not keep_meta:
        assert package_hash(bpak, pkg) == package_hash(bpak, pkg_one_part)
