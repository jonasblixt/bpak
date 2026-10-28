# bpak

Bitpacker: a C library (`lib/`, public headers in `include/bpak/`), a command
line tool (`src/`) and a python wrapper (`python/`) for signed firmware
archives. Developer documentation: `docs/dg/development-setup.rst`.

Open tasks are tracked in `todo.md`. Add tasks you discover there and move
them to Done, with the commit hash, when they are resolved.

## Build and test

```sh
cmake -B build -DBPAK_BUILD_TESTS=1
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure -j$(nproc)
ctest --test-dir build -L unit                     # or: cli, python
pytest test --bpak-build-dir build -k <pattern>    # tool/python tests directly
```

Tests require the full build (`BPAK_BUILD_MINIMAL=OFF`) and libmbedtls-dev,
liblzma-dev, uuid-dev, libcmocka-dev, python3-dev, python3-pytest and openssl.
If the dev packages are missing locally, build and test in a Debian or Ubuntu
container instead.

## Test layout

- `test/unit/` C unit tests using cmocka, one binary per file, linked against
  the static library and built with AddressSanitizer. Register new files in
  `UNIT_TESTS` in `test/unit/CMakeLists.txt`.
- `test/cli/` pytest tests of the `bpak` tool, `test/python/` pytest tests of
  the python wrapper. Register new files in `PYTEST_FILES` in
  `test/CMakeLists.txt`.
- `test/bpaktest.py` helpers and `test/conftest.py` fixtures, `test/data/`
  keys and reference files.

Things that are easy to get wrong in the pytest tests:

- The `bpak` fixture appends `-vvv`, and verbose logs go to stdout. Use
  `bpak.output(...)` when parsing a command's output.
- The tool exits with the negated `enum bpak_errors` value
  (`-BPAK_VERIFY_FAIL & 0xff == 236`). Use `bpak.fails(..., error=BpakError.X)`
  and add missing codes to `BpakError` in `test/bpaktest.py`.
- String meta data is stored with a trailing NUL byte.

## Version

`version.txt` is the single source of the version. `bpak/version.h` is
generated from `lib/version.h.in` into the build directory, never add a
version number anywhere else. Releases: update `version.txt`, commit as
`Version X.Y.Z` and tag `vX.Y.Z`.

## Conventions

- Commit subjects are prefixed with the area: `lib/verify: ...`, `python: ...`,
  `test: ...`, `docs: ...`.
- Bug fix commits are additionally prefixed with `bugfix:`, for example
  `bugfix: lib/mbedtls: Fix memory leaks when loading keys`. Keep bug fixes in
  separate commits from other changes.
- C code follows `.clang-format`, only format the code you change.
- Library functions log through `bpak_printf`, which is a weak symbol in
  `lib/bpak.c` that the tool, the python wrapper and the unit tests override.
