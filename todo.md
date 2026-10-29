# TODO

Open tasks for bpak. Add new tasks under the matching section with enough
context to pick them up later (file, function, why). When a task is done,
move it to **Done** with the commit that resolved it.

## Bugs

- [ ] The `bpak` tool prints `Error: [Errno 32] Broken pipe` and an ignored
      `BrokenPipeError` when its output is piped into a command that exits
      early, for example `bpak show demo.bpak | head -3`.
- [ ] `bpak generate keystore` writes a line with only spaces after the last
      byte of a key whose size is a multiple of 8, for example a secp384r1
      key (120 bytes), `generate_keystore` in `tools/bpak/cli.py`.
- [ ] `bpak_transport_encode` dereferences NULL when the origin or the
      input package has no `bpak-package` meta data: `bpak_get_meta_ptr` is
      called before `rc` is checked, and the size is not checked against
      the 16 bytes that are compared (`lib/transport_encode.c:375-396`).
      `transport_decode.c` does the same check correctly.
- [ ] Deleting an int attribute of the python wrapper segfaults, for
      example `del pkg.key_id`: the setters in `tools/_bpak/package.c`,
      `part.c` and `meta.c` call `PyLong_Check(value)` on NULL. They also
      truncate values that do not fit, `pkg.hash_kind = 256` reads back as
      0 and `pkg.key_id = 2**32 + 5` as 5; the `(uint32_t)x != x` checks in
      `part.c` and `meta.c` can never fail.
- [ ] Python wrapper details: `sign()` reports argument errors as
      `verify()` (`"O&:verify"` in `package.c`), `uuid_ctor` is not checked
      for NULL in `meta.c` and the docstring of `Package.meta` says "List of
      all parts".

## Release

- [ ] Release 1.0.0 from `work-1.0.0`: move the `Version 1.0.0` commit
      (0e6a0e8, in the middle of the branch) to the end with a rebase right
      before tagging `v1.0.0`, then update the commit hashes in this file.

## Build

- [ ] Publish wheels to PyPI. `uv build` creates wheels that link mbedtls
      and liblzma dynamically. manylinux wheels (cibuildwheel) need mbedtls
      and liblzma in the build image and auditwheel to bundle them.
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
      the file in between (documented in 64da07b). Consider a function that
      verifies the parts while it extracts them.
- [ ] `lib/pkg.c`, `lib/pkg_verify.c` and `lib/keystore_file.c` each have
      their own read callbacks for the same file reads
      (`pkg_read_payload`, `verify_payload_read`, `read_payload`,
      `decode_read_*`), merge them.

## Tests

- [ ] `cli.test_transport` takes ~17 s and dominates the test run. Every
      `bpak` command starts python and imports click (~55 ms), so the cli
      tests are ~2.5x slower than with the C tool. Consider pytest-xdist,
      splitting the scenarios into separate CTest tests or running the tool
      in-process with click's `CliRunner`.
- [ ] Check the full ABI of the shared library with libabigail (`abidiff`)
      against the last release. `test_abi` and `libbpak.symbols` cover the
      format, the public structs and the exported functions, but not
      function signatures or structs that embed internal state, like
      `struct bpak_transport_decode`.
- [ ] The python wrapper has no golden sample tests of its own, it is only
      tested against packages created by the current version.

## CI

- [ ] Show test results in the GitHub UI. The JUnit reports in
      `build/test/junit/` are only uploaded as an artifact when tests fail.
- [ ] Add clang to the CI test matrix. Needs the python wrapper to build
      with clang's `-Wextra -Werror`: `-Wmissing-field-initializers` on the
      `{NULL}` sentinels in the method/getset tables and an unused `idx` in
      `tools/_bpak/package.c`. Also install `libclang-rt-dev` for ASan.
- [ ] Run the tests on Windows (MSYS2); the Windows job only builds the
      minimal library today.

## Documentation

- [ ] `README.md` is the long description of the python package, its relative
      links and the logo do not work on PyPI.
- [ ] Check command examples in `docs/` automatically, for example a test that
      runs the `$ bpak` lines of `docs/user-guide.md`.

## Done

- [x] Replace Sphinx and Read the Docs with Markdown documentation (fb9b736)
- [x] Fix and complete the doc comments in the public headers (7cb6335)
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
      (806781f)
- [x] `bpak_pkg_write_raw_signature` overflowed the signature field
      (88db202)
- [x] Meta data larger than 65535 bytes overflowed the header in the python
      wrapper (9b5cf28)
- [x] Reference leaks in `Package.parts` and `Package.meta` (086a3cc)
- [x] Reading an empty part raised `OSError` (dbf3254)
- [x] Using a closed package crashed the python wrapper (69d6af0)
- [x] Errors in the python log function surfaced as `SystemError`
      (3e8a3a4)
- [x] The `bpak` tool failed to print file names that are not UTF-8
      (a9c1201)
- [x] `Part.read_data` reported "Success" for a short read (2ebcfea)
- [x] Clearing the signature ignored a failed header write (ae62986)
- [x] `pytest test --bpak-build-dir build` did not find the pytest
      configuration (edf1236)
- [x] Remove the dependency example, it used API that does not exist
      (41d321e)
- [x] Remove unused files and dependencies: the vendored libuuid code
      and the uuid-dev build dependency (b749de0), unused test keys
      (e18a8ff) and build leftovers (eecfc2a)
- [x] The python package did not declare or ship the MIT license of sais
      and the BSD-2-Clause license of bsdiff, and bsdiff, bspatch and
      heatshrink had lost their copyright notices (0666bbe)
- [x] Repository layout: third-party code in `lib/vendor` and sources named
      after their headers (8e47b4a), the python package in `tools/`, the C
      extension in `tools/_bpak` and the tool in `bpak.cli` (34f7fdb), compile options and include
      directories scoped to the targets (28eabca), the examples built and
      run as tests (291368b), unit tests named after what they test and the
      symbols in `test/abi` (0415eb5), `CHANGELOG.md` and anchored
      `.gitignore` patterns (5668f13)
- [x] Review of the library: bspatch overflowed buffers with
      negative lengths (4f15b3d) and offsets that do not fit `off_t`
      (73a31bb), the transport decoders wrote past the part and read past the
      origin part (7f5cac0)
- [x] `bpak_pkg_verify` passed an unchecked signature size to mbedtls
      (87373ee)
- [x] `bpak_del_meta` corrupted the following meta data and wrote past the
      meta data array (4122095)
- [x] `bpak_valid_header` accepted parts and meta data after an empty slot,
      unaligned meta data, overflowing part sizes and signature sizes, and
      parts with bad alignment (db5d88e)
- [x] Export `bpak_calloc`, `bpak_free` and `bpak_transport_encode`
      (55d5c99)
- [x] The lzma streams were created with the default allocator and the
      decoder had no memory limit (2221b28), keys from `bpak_calloc` were
      freed with `free` (dc59cdb)
- [x] `bpak_meta_to_string` did not terminate or initialize the buffer and
      ignored the meta data size (be95f4f)
- [x] Transport decoding did not compare the merkle root hash or check the
      merkle meta data sizes, and logged the tree offset with verbosity 0
      (5009b38)
- [x] bspatch returned -1 instead of error codes (0ab4f42)
- [x] `bpak_merkle_init` rejected trees with four levels and
      `bpak_merkle_write_chunk` did not bound its input (f4f8a06)
- [x] The merkle salt came from unseeded `random()` (fc164f7)
- [x] Fuzz targets for the code that parses untrusted input (da504e2) and
      the reproducers of their findings (06f7c6c)
- [x] Transport decoding leaked the lzma decoder when it stopped in the
      middle of a part (c805423)
- [x] Adding parts looped forever on short reads, wrote after transport
      encoded parts at the wrong offset, left the part on failure and
      computed the merkle tree from the file (bfe6923)
- [x] Deleting parts looped forever on short reads, moved the offsets by
      the transport size and stepped before the meta data array, a failed
      `bpak_pkg_open` left `pkg->fp` set and `pkg->filename` was never set
      (a24fc97)
- [x] `BPAK_DECLARE_STATIC_KEY` was not aligned (6850ec3)
- [x] The mbedtls backend ignored the results of mbedtls, including
      `mbedtls_pk_parse_public_keyfile` and the allocation in
      `bpak_mbed_load_public_key` (dced313)
- [x] `bpak_pkg_sign` signed into the header, did not clear the private key
      and did not set the signature kind of the key (e5d1552)
- [x] Keystore files: the payload hash was not verified, the provider id
      was read regardless of its size, an unknown key was `BPAK_NOT_FOUND`
      instead of `BPAK_KEY_NOT_FOUND` (b94c892)
- [x] Offsets were passed to `fseek` as `long`, programs with another size
      of `off_t` than the library fail to compile (1165d79)
- [x] Programs with other mbedtls headers than the library fail to compile
      (aee4db4)
- [x] The static library defined the heatshrink and sais functions without
      a prefix (e093956)
- [x] The part loops stopped or skipped at empty slots, they all end at the
      first empty slot (8766c47)
- [x] `bpak_pkg_size` and `bpak_pkg_installed_size` wrapped around (6182e5e)
- [x] `bpak.transport_decode` cleared the transport flags in the header of
      the input package, and the output package kept its old header
      (78933d6)
- [x] `bpak delete --part` left the `<part>-hash-tree` part of a merkle
      part (517782a)
- [x] `bpak set --meta` could not change meta data of a part, it has
      `--part-ref` (336fdf1)
- [x] `bpak_mbed_verify` returns `BPAK_OK` for a signature that does not
      match, which is the contract of `bpak_crypto_verify`, the unused
      `-BPAK_VERIFY_FAIL` is removed (2dbfa0a)
- [x] Checked both library reviews against the fixes: bsdiff truncated
      matches longer than 2 GiB (9d95826), documented what verification
      and transport decoding cover (64da07b)
