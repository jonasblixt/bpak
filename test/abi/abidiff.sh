#!/bin/sh
# Compare the ABI of the shared library in the working tree with a release.
#
#   test/abi/abidiff.sh [REF]
#
# Builds libbpak from REF, by default the last release tag before HEAD, and
# from the working tree with debug information and compares them with
# abidiff from libabigail. Both are built with the same compiler and mbedtls
# headers, so that struct bpak_hash_context, which embeds the mbedtls
# contexts, is compared too. All changes are reported, but only removed
# functions fail the check. Changed types, for example a struct with new
# members, are allowed, see "Compatibility" in docs/development.md.

set -eu

SOURCE_DIR=$(cd "$(dirname "$0")/../.." && pwd)
REF=${1:-$(git -C "$SOURCE_DIR" describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^)}

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

build() {
    src=$1
    out=$2
    cmake -S "$src" -B "$out" -DCMAKE_BUILD_TYPE=Debug -DBPAK_WERROR=OFF \
        -DCMAKE_C_FLAGS="-g -Og" > "$out.log" 2>&1
    cmake --build "$out" --target bpak -j "$(nproc)" >> "$out.log" 2>&1 ||
        { cat "$out.log"; exit 1; }
}

# The ABI of the library: the functions it exports and the types in the
# public headers
dump() {
    src=$1
    out=$2
    lib=$(find "$out/lib" -name 'libbpak.so.*.*' -type f)
    set -- --headers-dir "$src/include/bpak"
    if [ -d "$out/include/bpak" ]; then
        set -- "$@" --headers-dir "$out/include/bpak"
    fi
    abidw "$@" --out-file "$out.abi" "$lib"
}

echo "Comparing the ABI of $REF with the working tree"

mkdir "$WORK_DIR/old"
git -C "$SOURCE_DIR" archive "$REF" | tar -x -C "$WORK_DIR/old"
build "$WORK_DIR/old" "$WORK_DIR/old-build"
dump "$WORK_DIR/old" "$WORK_DIR/old-build"

build "$SOURCE_DIR" "$WORK_DIR/new-build"
dump "$SOURCE_DIR" "$WORK_DIR/new-build"

# Report all changes, but only fail for removed functions. abidiff sets bit
# 3 of the exit status for removed functions and a changed SONAME, which is
# ignored, type changes set bit 2 like added functions do.
abidiff "$WORK_DIR/old-build.abi" "$WORK_DIR/new-build.abi" || true

status=0
abidiff --no-added-syms --ignore-soname "$WORK_DIR/old-build.abi" \
    "$WORK_DIR/new-build.abi" > /dev/null || status=$?

if [ $((status & 8)) -ne 0 ]; then
    echo "Functions of $REF were removed" >&2
    exit 1
fi
if [ $((status & 3)) -ne 0 ]; then
    echo "abidiff failed" >&2
    exit 1
fi
if [ "$status" -ne 0 ]; then
    echo "The ABI changed since $REF, see the report above"
else
    echo "The ABI is compatible with $REF"
fi
