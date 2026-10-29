#!/bin/sh
# Compare the ABI of the shared library in the working tree with a release.
#
#   test/abi/abidiff.sh [REF]
#
# Builds libbpak from REF, by default the last release tag before HEAD, and
# from the working tree with debug information and compares them with
# abidiff from libabigail. Both are built with the same compiler and mbedtls
# headers, so that struct bpak_hash_context, which embeds the mbedtls
# contexts, is compared too. Added functions are reported but do not fail,
# removed or changed functions and types and a changed SONAME do.

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

# Report all changes, but only fail for changes other than added functions.
# abidiff sets bit 3 of the exit status only for removed functions and a
# changed SONAME, type changes set bit 2 like added functions do.
abidiff "$WORK_DIR/old-build.abi" "$WORK_DIR/new-build.abi" || true

if ! abidiff --no-added-syms "$WORK_DIR/old-build.abi" \
        "$WORK_DIR/new-build.abi" > /dev/null; then
    echo "The ABI is not compatible with $REF" >&2
    exit 1
fi
echo "The ABI is compatible with $REF"
