# Development

## Prerequisites

On Debian or Ubuntu everything that is needed to build bpak and run the tests
can be installed with:

```
$ sudo apt install build-essential cmake pkg-config \
      libmbedtls-dev liblzma-dev \
      libcmocka-dev python3-dev python3-pytest python3-click openssl lcov \
      clang-format
```

Other distributions provide the same libraries under similar names: mbedtls,
liblzma, cmocka, click and the python3 development headers. Python 3.10 or
later is required.

The python package is developed with [uv](https://docs.astral.sh/uv).
`uv sync` creates a virtual environment in `.venv` with the pinned
development tools from `uv.lock` (the `dev` dependency group in
`pyproject.toml`) and an editable install of bpak:

```
$ uv sync
$ uv run bpak --help
```

The editable install builds the C extension with scikit-build-core and CMake.
`uv sync` rebuilds it when C sources change, see `tool.uv.cache-keys` in
`pyproject.toml`.

CMake picks up an active virtual environment, so the system packages for
pytest and click are not needed when `.venv` is activated before configuring:

```
$ . .venv/bin/activate
$ cmake -B build -DBPAK_BUILD_TESTS=1
```

## Building

Configure a build directory with the tests enabled and build it:

```
$ cmake -B build -DBPAK_BUILD_TESTS=1
$ cmake --build build -j$(nproc)
```

`BPAK_BUILD_TESTS` also builds `bpak._bpak`, the C extension of the python
package, and compiles the library with coverage instrumentation. The C unit
tests are built with AddressSanitizer, which includes leak detection, but the
library and the C extension are built without sanitizers.

The `bpak` tool is implemented in python, in `tools/bpak/cli.py`. It uses
the python package in `tools/bpak`, which wraps the C extension
`bpak._bpak` (`tools/_bpak/`, typed in `tools/bpak/_bpak.pyi`). The build
directory holds the package in `build/tools/bpak`, the extension and links
to the python sources. Run the tool from there without installing it:

```
$ PYTHONPATH=build/tools python3 -m bpak --help
```

Build a source distribution and a wheel of the python package into `dist/`:

```
$ uv build
```

## Running tests

Run the complete test suite:

```
$ ctest --test-dir build --output-on-failure -j$(nproc)
```

Every C unit test binary and every pytest file is a separate CTest test. The
tests are labeled by group, use `ctest -L <label>` to run one group:

| Label      | Description                                     | Location      |
|------------|-------------------------------------------------|---------------|
| `unit`     | C unit tests of the library (cmocka)            | `test/unit`   |
| `cli`      | Tests of the bpak tool (pytest)                 | `test/cli`    |
| `python`   | Tests of the python package (pytest)            | `test/python` |
| `golden`   | Golden sample packages                          | `test/golden` |
| `abi`      | Functions exported by the shared library        | `test/abi`    |
| `examples` | Build and run the examples                      | `examples`    |
| `fuzz`     | Seed corpus and reproducers of the fuzz targets | `test/fuzz`   |

The pytest based tests can be run directly against a build directory, which
gives access to all pytest options:

```
$ pytest test --bpak-build-dir build
$ pytest test --bpak-build-dir build -k transport -v
$ pytest test/cli/test_sign.py --bpak-build-dir build -x
```

Setting the environment variable `BPAK_BUILD_DIR` replaces
`--bpak-build-dir`.

Without a build directory the tests of the tool and the python package run
against the installed bpak package, for example the editable install of
`uv sync`. Tests that need files from the CMake build are skipped:

```
$ uv run pytest test/cli test/python test/golden
```

A C unit test binary can be run on its own to see the result of every test
case:

```
$ ./build/test/unit/test_merkle
```

When the tests are run through CTest, the files created by each pytest test
are kept in `build/test/pytest/<test name>/` and JUnit reports are written to
`build/test/junit/`.

## Writing tests

Test data such as keys and reference files is stored in `test/data`.

### C unit tests

Unit tests use [cmocka](https://cmocka.org) and are linked against the
static library, so internal symbols are available. A test file defines its
tests as `static void test_name(void **state)` functions and runs them from
`main`:

```c
#include "test_helpers.h"

static void test_something(void **state)
{
    (void)state;
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_something),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

`TEST_DATA("file")` expands to the path of a file in `test/data` and
`test_load_file()` reads a whole file into memory. `test/unit/test_helpers.h`
has more helpers, for example for temporary files, headers with meta data
and parts, bspatch control data and an allocator that checks that the
library frees what it allocates. New test files must be added to
`UNIT_TESTS` in `test/unit/CMakeLists.txt`.

### Tool and python package tests

These tests use [pytest](https://pytest.org). Every test runs in its own
temporary directory. Shared helpers are in `test/bpaktest.py` and fixtures in
`test/conftest.py`:

- `bpak` runs the bpak tool: `python -m bpak` with the python package from
  the source tree and the C extension from the build directory.
  `bpak("show", pkg)` runs a command with `-vvv` and fails the test if it
  returns an error. Verbose logs are written to stdout, so use
  `bpak.output(...)` to run a command without them and get its output.
  `bpak.fails(..., error=BpakError.VERIFY_FAIL)` expects a command to fail
  with a specific error; the tool exits with the negated `enum bpak_errors`
  value and with 2 for usage errors. `bpak.create_package(...)` creates and
  signs a package with optional parts and transport rules.
- `make_data` creates a file with a given number of KiB of test data.
- `random_data` creates an origin and a target file of pseudo-random data
  that differ, for transport encoding. `random_bytes()` in `bpaktest.py`
  returns pseudo-random data that is the same in every run, generate large
  test data with it instead of committing it to `test/data`.
- `keystore` is a copy of the keystore of the golden set 0.9.3 with the
  public keys in `test/data` and the keystore id `pb-internal`.
- `pybpak` is the bpak python package with the C extension from the build
  directory (`test/python` only). The `origin_pkg` and `target_pkg` fixtures
  provide signed packages to test against.

Parametrize tests that only differ in their input instead of duplicating
them. New test files must be added to `PYTEST_FILES` in
`test/CMakeLists.txt`.

### Fuzz targets

The code that parses untrusted input has [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
targets in `test/fuzz`, one file per target:

| Target      | Input                                                        |
|-------------|--------------------------------------------------------------|
| `header`    | A header, checked with `bpak_valid_header` and then used with the meta data and part functions |
| `bspatch`   | Compression, chunk length and a patch for a fixed origin     |
| `verify`    | A package, verified with `bpak_pkg_verify` and `bpak_verify_payload` |
| `transport` | A transport encoded package, decoded against `test/golden/0.9.3/origin.bpak` |

The targets abort when the library breaks a contract, for example when a
callback gets a length larger than the buffer, and AddressSanitizer and
UndefinedBehaviorSanitizer report memory errors.

Test builds run every file in `test/fuzz/corpus/<target>` through the target,
label `fuzz`, with `test/fuzz/driver.c` instead of libFuzzer. The golden
packages in `test/golden/0.9.3` are part of the seed corpus of the `header`,
`transport` and `verify` targets, `test/fuzz/CMakeLists.txt` lists the
packages each target runs. Add the reproducer of every bug a fuzzer finds to
the corpus. Set `BPAK_FUZZ_VERBOSE=2` to see the log of the library:

```
$ BPAK_FUZZ_VERBOSE=2 build/test/fuzz/fuzz_bspatch_corpus crash-file
```

The fuzzers need clang, configure a separate build directory with
`BPAK_BUILD_FUZZERS`, which also builds the library with the sanitizers:

```
$ cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DBPAK_BUILD_FUZZERS=ON
$ cmake --build build-fuzz -j$(nproc)
$ mkdir -p corpus && cp test/fuzz/corpus/bspatch/* corpus/
$ build-fuzz/test/fuzz/fuzz_bspatch -max_total_time=600 corpus
```

Seed the `header`, `transport` and `verify` targets with the golden packages
as well:

```
$ mkdir -p corpus && cp test/fuzz/corpus/transport/* test/golden/0.9.3/*.bpak corpus/
$ build-fuzz/test/fuzz/fuzz_transport -max_total_time=600 corpus
```

On Debian and Ubuntu install `clang` and `libclang-rt-dev`, or run the
commands in a container:

```
$ docker run --rm -it -v $PWD:/src -w /src debian:trixie sh -c \
    'apt-get update && apt-get install -y clang libclang-rt-dev cmake \
     pkg-config libmbedtls-dev liblzma-dev && sh'
```

## Compatibility

Packages, patches and keystores live for a long time. Devices in the field
run old versions of bpak, bootloaders are rarely updated and patches are
created by newer versions than the ones that apply them. The package format
and the ABI of the library must never change in an incompatible way. These
tests guard this:

- `test/unit/test_abi.c` checks the layout of the structs in the public
  headers and the values of all enums, constants and predefined ids.
- `test/abi/libbpak.symbols` lists the functions that the shared library
  exports, `test/abi/test_symbols.py` checks that it still exports them and
  nothing that is not listed.
- `test/golden` holds golden sample packages. Every directory holds
  packages, patches and a keystore that were created by a release, together
  with the input files and the commands that created them. All later
  versions must read, verify and decode them, and must create identical
  packages and patches from the same commands.

Never change an expected value or a golden set to make these tests pass.
When a release adds to the format, for example a new encoder or a new kind of
meta data, extend `test/golden/generate.py` and add a new golden set for the
release. The set is named after `version.txt`:

```
$ test/golden/generate.py --bpak-build-dir build
```

New functions that the library exports are added to
`test/abi/libbpak.symbols`.

## Coverage

Builds with `BPAK_BUILD_TESTS` produce coverage data when the tests are run.
Create an HTML report with lcov:

```
$ lcov --directory build --capture --output-file coverage.info
$ genhtml coverage.info --output-directory coverage_report
```

## Code style

C code is formatted with clang-format using the `.clang-format` file in the
repository root. Only format the code you change. Third-party code is kept
in `lib/vendor/`, one directory per project, its license is in `LICENSES/`.

The python package is checked with [ruff](https://docs.astral.sh/ruff) and
[mypy](https://mypy-lang.org), configured in `pyproject.toml`. stubtest
checks that the type stub of the C extension matches the extension:

```
$ uv run ruff check
$ uv run ruff format --check
$ uv run mypy
$ uv run python -m mypy.stubtest bpak._bpak
```

## Documentation

The documentation is written in Markdown: `README.md` and the pages in
`docs/`. The C API is documented in the public headers in `include/bpak/`
and the python API in the type stub `tools/bpak/_bpak.pyi`. Update the
documentation in the same commit as the change it describes, and make sure
that command examples and their output match the current tool.

## Contributing

1. Fork the repository and create a branch from `master`.
2. Implement the feature or bug fix, with tests that make sure that later
   changes do not break it. Describe changes that affect users in
   `CHANGELOG.md` and update the documentation.
3. Run the tests and the linters.
4. Create a pull request.

Open tasks and known bugs are tracked in `todo.md`. Add the tasks you find
there, and move a task to *Done* with the commit that resolves it.

## Commit messages

The first line of a commit message is prefixed with the area that the commit
changes, followed by a short summary:

```
lib/verify: Compare the entire root hash not just the first byte
test: Replace nala and shell scripts with cmocka and pytest
docs: Describe how to run the tests
```

Bug fixes are additionally prefixed with `bugfix:`:

```
bugfix: lib/mbedtls: Fix memory leaks when loading keys
```

Keep bug fixes in separate commits from other changes.

## Versioning

bpak follows [semantic versioning](https://semver.org). `version.txt` in
the repository root holds the version in the form `MAJOR.MINOR.PATCH` and is
the only place where it is defined. It is used for:

- the CMake project version, the shared library version and the pkg-config
  file
- `bpak/version.h` (`BPAK_VERSION_MAJOR`, `BPAK_VERSION_STRING`, ...), which
  is generated into the build directory
- the python package version, read by scikit-build-core, see
  `pyproject.toml`

Builds that do not use CMake (`BPAK_HAVE_USER_SETTINGS`) must provide their
own `bpak/version.h`, see `lib/version.h.in`.

To make a release, update `version.txt` and the heading of the release in
`CHANGELOG.md`, commit them as `Version X.Y.Z` and tag the commit `vX.Y.Z`.
Add changes that affect users to `CHANGELOG.md` when they are made.
