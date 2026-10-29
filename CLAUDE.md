# bpak

Bitpacker: a C library (`lib/`, public headers in `include/bpak/`,
third-party code in `lib/vendor/`) and a python package (`python/bpak/`)
with the `bpak` command line tool (`python/bpak/__main__.py`, click) for
signed firmware archives. The package
wraps the C extension `_bpak` (`python/*.c`). Documentation is Markdown in
`README.md` and `docs/`, developer documentation in `docs/development.md`.

Open tasks are tracked in `todo.md`. Add tasks you discover there and move
them to Done, with the commit hash, when they are resolved.

## Build and test

```sh
cmake -B build -DBPAK_BUILD_TESTS=1
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure -j$(nproc)
ctest --test-dir build -L unit                     # or: cli, python, golden, abi, examples
pytest test --bpak-build-dir build -k <pattern>    # tool/python tests directly
PYTHONPATH=build/python python3 -m bpak           # run the tool from the build

uv sync                                           # .venv, editable install, dev tools
uv run pytest test/cli test/python test/golden    # against the editable install
uv run ruff check && uv run ruff format --check && uv run mypy
uv run python -m mypy.stubtest bpak._bpak         # stub matches the C extension
uv build                                          # sdist and wheel in dist/
```

The python package is built with scikit-build-core from the CMake build
(`pyproject.toml`), dependencies are locked in `uv.lock`. Run `uv lock` after
changing dependencies.

Tests require the full build (`BPAK_BUILD_MINIMAL=OFF`) and libmbedtls-dev,
liblzma-dev, libcmocka-dev, python3-dev, python3-pytest,
python3-click and openssl. Instead of python3-pytest and python3-click, `uv sync`
and configure with `.venv` activated.
If the dev packages are missing locally, build and test in a Debian or Ubuntu
container instead.

## Test layout

- `test/unit/` C unit tests using cmocka, one binary per file, linked against
  the static library and built with AddressSanitizer. Register new files in
  `UNIT_TESTS` in `test/unit/CMakeLists.txt`.
- `test/cli/` pytest tests of the `bpak` tool, `test/python/` pytest tests of
  the python package. Register new files in `PYTEST_FILES` in
  `test/CMakeLists.txt`.
- `test/golden/` golden sample packages created by released versions and
  `test/abi/` the exported symbols, see "Compatibility" below.
  `test/bpaktest.py` helpers and `test/conftest.py` fixtures, `test/data/`
  keys and reference files.
- `examples/` are built and run as tests, label `examples`.

Things that are easy to get wrong in the pytest tests:

- The `bpak` fixture runs `python -m bpak` and appends `-vvv`, verbose logs
  go to stdout. Use `bpak.output(...)` when parsing a command's output.
- The tool exits with the negated `enum bpak_errors` value
  (`-BPAK_VERIFY_FAIL & 0xff == 236`), usage errors with 2. Use
  `bpak.fails(..., error=BpakError.X)` and add missing codes to `BpakError` in
  `test/bpaktest.py`.
- String meta data is stored with a trailing NUL byte.

## Compatibility

The package format and the library ABI must never break: old packages,
patches and keystores must keep working with new versions and new patches
must work with old decoders. The options of the `bpak` tool must stay
compatible, `test/golden` replays recorded command lines.
`test/unit/test_abi.c` checks struct layouts, enums and ids, `test/golden/`
checks committed packages from earlier releases and `test/abi/` the exported
symbols (`libbpak.symbols`). Never update expected values or golden sets to
make these tests pass. Add a new golden set with `test/golden/generate.py`
when a release extends the format, and add new exported functions to
`test/abi/libbpak.symbols`.

## Version

`version.txt` is the single source of the version. `bpak/version.h` is
generated from `lib/version.h.in` into the build directory, never add a
version number anywhere else, except the release headings in
`CHANGELOG.md`. Add changes that affect users to `CHANGELOG.md` with the
change. Releases: update `version.txt` and the release heading in
`CHANGELOG.md`, commit as `Version X.Y.Z` and tag `vX.Y.Z`.

## Conventions

- Commit subjects are prefixed with the area: `lib/verify: ...`, `python: ...`,
  `test: ...`, `docs: ...`.
- Bug fix commits are additionally prefixed with `bugfix:`, for example
  `bugfix: lib/mbedtls: Fix memory leaks when loading keys`. Keep bug fixes in
  separate commits from other changes.
- C code follows `.clang-format`, only format the code you change. Keep the
  copyright notices in third-party code and its license in `LICENSES/`. Python
  code in `python/bpak` follows ruff and strict mypy (`pyproject.toml`).
- New error codes need an exception in `python/exceptions.c`,
  `python/bpak/__init__.py` and `python/bpak/_bpak.pyi`. Changes to the C
  extension API must be reflected in the stub `python/bpak/_bpak.pyi`.
- Documentation is plain Markdown, the C API is documented in the public
  headers. Update `docs/` in the same commit as the change it describes and
  keep the commands and their output in `docs/user-guide.md` in sync with the
  tool.
- Library functions log through `bpak_printf`, which is a weak symbol in
  `lib/bpak.c` that the python extension and the unit tests override.
