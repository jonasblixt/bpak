# TODO

Open tasks for bpak. Add new tasks under the matching section with enough
context to pick them up later (file, function, why). When a task is done,
move it to **Done** with the commit that resolved it.

## Bugs

## Release

## Build

- [ ] Before the first upload: create the `pypi` environment with the
      `PYPI_API_TOKEN` and `TEST_PYPI_API_TOKEN` secrets in the GitHub
      repository. The project does not exist on PyPI yet, so the first
      upload needs a token scoped to the account; replace it with a
      project-scoped token afterwards. Try the upload with a manual run of
      `wheels.yml` (TestPyPI) first.
- [ ] Use trusted publishing for the PyPI uploads instead of API tokens,
      in `wheels.yml` and in punchboot.
- [ ] Build wheels for macOS and Windows. The wheels are Linux only, other
      platforms build the sdist and need mbedtls and liblzma installed.
      `tools/wheels/install-deps.sh` builds mbedtls from source and could do
      the same on macOS, liblzma would also have to be built for the
      deployment target.
- [ ] `BPAK_BUILD_MINIMAL` builds only the core, but the verify, merkle,
      transport decode and bspatch sources have no dependencies either and
      are what a bootloader uses. Consider adding them to the minimal build,
      the Windows CI job would then build them too.
- [ ] Add an option to build the library and tool with AddressSanitizer and
      UndefinedBehaviorSanitizer. Today only the unit test code is
      instrumented.

## Library

- [ ] `bpak_pkg_verify` verifies the file and `bpak_pkg_extract_file` reads
      it again, so the extracted data is only covered when nothing changes
      the file in between (documented in fcfdca9). Consider a function that
      verifies the parts while it extracts them.

## Tests

- [ ] `cli.test_transport` takes ~17 s and dominates the test run. Every
      `bpak` command starts python and imports click (~55 ms), so the cli
      tests are ~2.5x slower than with the C tool. Consider pytest-xdist,
      splitting the scenarios into separate CTest tests or running the tool
      in-process with click's `CliRunner`.

## CI

- [ ] Show test results in the GitHub UI. The JUnit reports in
      `build/test/junit/` are only uploaded as an artifact when tests fail.
- [ ] Add clang to the CI test matrix, install `libclang-rt-dev` for ASan.
      The `{NULL}` sentinels and the unused `idx` that broke clang's
      `-Wextra -Werror` in the python wrapper are fixed (58683cc, 15e6330),
      but the build is not yet tested with clang.
- [ ] Run the tests on Windows (MSYS2); the Windows job only builds the
      minimal library today.

## Documentation

- [ ] Check command examples in `docs/` automatically, for example a test that
      runs the `$ bpak` lines of `docs/user-guide.md`.

## Done

- [x] Replace Sphinx and Read the Docs with Markdown documentation (7ba5469)
- [x] Fix and complete the doc comments in the public headers (d911248)
- [x] Replace nala and the shell script tests with cmocka and pytest (b0b4bfe)
- [x] Fix memory leaks when loading keys in the mbedtls wrapper (143724e)
- [x] Keep a reference to the python log callback (cf95611)
- [x] Development setup guide and CLAUDE.md (b1151fe)
- [x] Zero padding after keys, it contained stack memory (d4a0373)
- [x] RSA keys in keystores crashed verification (5c00cab)
- [x] Transport decode did not detect origins from other packages (e406f63)
- [x] Buffer overflow in `bpak_bin2hex` and `bpak show` (45e632b)
- [x] `bpak_verify_compute_header_hash` ignored errors (011b2a7)
- [x] Extracting transport encoded parts truncated them (766be4e)
- [x] `bpak transport` used an uninitialized origin without `--origin`
      (30dfe43)
- [x] Opening a small file that is not a package modified it (733d098)
- [x] ABI tests (0633cca) and golden sample packages (eb0c11d)
- [x] Opening a file that is not a package crashed the python wrapper
      (db5caf7)
- [x] `add_meta` in the python wrapper released string data twice when the
      header could not be written (4fd723d)
- [x] Package the python wrapper with scikit-build-core and uv, replaces
      the non-existent `BPAK_BUILD_PYTHON_WRAPPER` in the docs (b0a5e34)
- [x] Replace the C tool with a python implementation, which removes the
      leaks in `src/transport.c` (91a4eaf)
- [x] A failed `bpak_add_meta` left a meta data entry in the header
      (f8267f5)
- [x] `bpak_pkg_write_raw_signature` overflowed the signature field
      (3028fd1)
- [x] Meta data larger than 65535 bytes overflowed the header in the python
      wrapper (5fa3fe9)
- [x] Reference leaks in `Package.parts` and `Package.meta` (c19a5e6)
- [x] Reading an empty part raised `OSError` (5b45ac1)
- [x] Using a closed package crashed the python wrapper (76c42f3)
- [x] Errors in the python log function surfaced as `SystemError`
      (b603308)
- [x] The `bpak` tool failed to print file names that are not UTF-8
      (50c18ae)
- [x] `Part.read_data` reported "Success" for a short read (51dd704)
- [x] Clearing the signature ignored a failed header write (bcc94e1)
- [x] `pytest test --bpak-build-dir build` did not find the pytest
      configuration (bfab8d9)
- [x] Remove the dependency example, it used API that does not exist
      (23087d6)
- [x] Remove unused files and dependencies: the vendored libuuid code
      and the uuid-dev build dependency (3757d47), unused test keys
      (bbad870) and build leftovers (069bdae)
- [x] The python package did not declare or ship the MIT license of sais
      and the BSD-2-Clause license of bsdiff, and bsdiff, bspatch and
      heatshrink had lost their copyright notices (3175bd5)
- [x] Repository layout: third-party code in `lib/vendor` and sources named
      after their headers (970e20d), the python package in `tools/`, the C
      extension in `tools/_bpak` and the tool in `bpak.cli` (ea858ae), compile options and include
      directories scoped to the targets (57afcb0), the examples built and
      run as tests (719e6f9), unit tests named after what they test and the
      symbols in `test/abi` (b0fe219), `CHANGELOG.md` and anchored
      `.gitignore` patterns (e05ede9)
- [x] Review of the library: bspatch overflowed buffers with
      negative lengths (d773293) and offsets that do not fit `off_t`
      (dca6e64), the transport decoders wrote past the part and read past the
      origin part (e8ca99d)
- [x] `bpak_pkg_verify` passed an unchecked signature size to mbedtls
      (850b030)
- [x] `bpak_del_meta` corrupted the following meta data and wrote past the
      meta data array (9bc37f7)
- [x] `bpak_valid_header` accepted parts and meta data after an empty slot,
      unaligned meta data, overflowing part sizes and signature sizes, and
      parts with bad alignment (f8b1895)
- [x] Export `bpak_calloc`, `bpak_free` and `bpak_transport_encode`
      (d5168c3)
- [x] The lzma streams were created with the default allocator and the
      decoder had no memory limit (071cd00), keys from `bpak_calloc` were
      freed with `free` (9be4db9)
- [x] `bpak_meta_to_string` did not terminate or initialize the buffer and
      ignored the meta data size (43caf0d)
- [x] Transport decoding did not compare the merkle root hash or check the
      merkle meta data sizes, and logged the tree offset with verbosity 0
      (0d37a21)
- [x] bspatch returned -1 instead of error codes (5a1d19b)
- [x] `bpak_merkle_init` rejected trees with four levels and
      `bpak_merkle_write_chunk` did not bound its input (d4278ad)
- [x] The merkle salt came from unseeded `random()` (f5b9bce)
- [x] Fuzz targets for the code that parses untrusted input (cf8a0ee) and
      the reproducers of their findings (5c9fb45)
- [x] Transport decoding leaked the lzma decoder when it stopped in the
      middle of a part (0a2527a)
- [x] Adding parts looped forever on short reads, wrote after transport
      encoded parts at the wrong offset, left the part on failure and
      computed the merkle tree from the file (719a1da)
- [x] Deleting parts looped forever on short reads, moved the offsets by
      the transport size and stepped before the meta data array, a failed
      `bpak_pkg_open` left `pkg->fp` set and `pkg->filename` was never set
      (692df71)
- [x] `BPAK_DECLARE_STATIC_KEY` was not aligned (483c1dc)
- [x] The mbedtls backend ignored the results of mbedtls, including
      `mbedtls_pk_parse_public_keyfile` and the allocation in
      `bpak_mbed_load_public_key` (a8ae6ab)
- [x] `bpak_pkg_sign` signed into the header, did not clear the private key
      and did not set the signature kind of the key (12177fe)
- [x] Keystore files: the payload hash was not verified, the provider id
      was read regardless of its size, an unknown key was `BPAK_NOT_FOUND`
      instead of `BPAK_KEY_NOT_FOUND` (d7efa1f)
- [x] Offsets were passed to `fseek` as `long`, programs with another size
      of `off_t` than the library fail to compile (bcd8bfd)
- [x] Programs with other mbedtls headers than the library fail to compile
      (de43a99)
- [x] The static library defined the heatshrink and sais functions without
      a prefix (5dc39d4)
- [x] The part loops stopped or skipped at empty slots, they all end at the
      first empty slot (7b3bf84)
- [x] `bpak_pkg_size` and `bpak_pkg_installed_size` wrapped around (e72e687)
- [x] `bpak.transport_decode` cleared the transport flags in the header of
      the input package, and the output package kept its old header
      (18a11f3)
- [x] `bpak delete --part` left the `<part>-hash-tree` part of a merkle
      part (d0aee80)
- [x] `bpak set --meta` could not change meta data of a part, it has
      `--part-ref` (d340a2e)
- [x] `bpak_mbed_verify` returns `BPAK_OK` for a signature that does not
      match, which is the contract of `bpak_crypto_verify`, the unused
      `-BPAK_VERIFY_FAIL` is removed (124fe83)
- [x] Checked both library reviews against the fixes: bsdiff truncated
      matches longer than 2 GiB (ec648b3), documented what verification
      and transport decoding cover (fcfdca9)
- [x] `bpak_transport_encode` dereferenced NULL without `bpak-package` meta
      data (3ddc38a) and returned -1 instead of error codes (4c9efe1), wrong
      printf formats in log messages (92634e6), the public headers were not
      installed when built as a subproject (8eb0f31), `key.h` did not
      include the headers it uses (798493c)
- [x] Deleting an int attribute of the python wrapper segfaulted and
      values that did not fit were truncated (75892f4), `sign()` errors
      named `verify()` and an unchecked `uuid_ctor` (f88cb2c), ids and sizes
      were converted with `long` (8d7e342)
- [x] Code review for things to drop or de-duplicate:
      - tests: generated transport test data instead of 4.8 MB of committed
        files, duplicated tests, fuzz corpus and helpers removed
        (2a206bc..a16dc50)
      - library: shared helpers in `lib/internal.h`, merged read and write
        callbacks (01d2918), dead heatshrink code, sources compiled once
        (cce68dd..fc29e85)
      - python: shared getters, setters, lookups and conversions in the
        extension, `Part.id`, `Meta.id` and `Meta.part_id_ref` read-only,
        star import in `__init__.py`, shared options in `cli.py`
        (f475125..c71f0ae)
      - CI: the pip-install job tests the sdist in python-package (fd9b6ad)
- [x] `bpak show | head` printed a `BrokenPipeError` (2ed0556)
- [x] `bpak generate keystore` wrote trailing spaces and a line with only
      spaces after keys whose size is a multiple of 8 (71b10ac)
- [x] Compare the full ABI with the last release with abidiff, CI job `abi`
      (5040131)
- [x] Golden sample tests for the python package (b850cbf)
- [x] Wheels with cibuildwheel and uploads to PyPI, absolute links in
      `README.md` for the description on PyPI (aaefdbd)
- [x] Release 1.0.0, tag `v1.0.0`
