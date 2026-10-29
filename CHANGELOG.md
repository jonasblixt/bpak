# Changelog

Changes that affect users of the library, the python package and the `bpak`
tool. The package format and the library ABI stay compatible, see
[Compatibility](docs/development.md#compatibility).

## 1.0.0 (unreleased)

### Added

- `bpak set --part-ref` changes meta data that refers to a part, for
  example `pb-load-addr`. `set` could only change meta data without a part
  reference.
- `bpak_id_to_string` knows `bpak-key-id` and `bpak-key-store`, which
  `bpak show` prints as the names of such meta data.

### Changed

- The `bpak` tool is implemented in python and is part of the `bpak` python
  package, install it with `pip install .` or `uv tool install .`. The C
  implementation in `src/` is removed. Commands and options are unchanged,
  but usage errors exit with 2, and `bpak compare` marks parts that only
  exist in the second package with `+` instead of `-`.
- The python wrapper is the `bpak` python package, built with
  scikit-build-core and CMake. It links the library statically, requires
  Python 3.10 or later and is typed. It replaces `python/setup.py`.
- The documentation is Markdown in `docs/`, which replaces Sphinx and Read
  the Docs. The public headers document the complete C API.
- libuuid is no longer a build dependency.
- `version.txt` holds the version.
- The python package declares and ships the licenses of the third-party
  code, see `LICENSES/`.
- Programs that are compiled with other mbedtls headers than the library
  fail to compile, `struct bpak_hash_context` contains the mbedtls contexts.
- `bpak_printf` is declared with the `format(printf)` attribute, compilers
  check the arguments of calls to it.
- `bpak/heatshrink_decoder.h` only defines the decoder state that
  `struct bpak_bspatch_context` embeds. The declarations of the heatshrink
  functions, which the library does not export, and `HEATSHRINK_USE_INDEX`
  are removed.

### Fixed

- Merkle tree verification compared only the first byte of the root hash.
- Verifying a package against a keystore with an RSA key crashed.
- A patch was not detected when applied to an origin from another package.
- Opening a file smaller than a header that is not a package wrote a header
  into it.
- Keystores contained stack memory in the padding after keys.
- `bpak_bin2hex` and `bpak show` could overflow a buffer.
- Extracting a transport encoded part truncated it.
- `bpak transport` used an uninitialized origin without `--origin`.
- `bpak_verify_compute_header_hash` ignored errors.
- A failed `bpak_add_meta` left a meta data entry in the header, and
  `bpak_pkg_write_raw_signature` could overflow the signature field.
- Memory leaks when loading keys with mbedtls, and compiler warnings in 32-bit
  builds.
- A patch with negative lengths in its control data overflowed buffers when
  it was applied, for example with `bpak transport --decode`. Such patches
  fail with `BPAK_SIZE_ERROR`, as do patches that seek before the origin.
- `bpak_pkg_verify` read past the signature field when the signature size in
  the header was larger than the field, it fails with `BPAK_SIZE_ERROR`.
- Deleting meta data, for example with `bpak delete --part`, corrupted the
  value of the following meta data when it was larger than the deleted one,
  and with 32 meta data entries it cleared the first part header.
- `bpak_valid_header` accepted parts and meta data after an empty slot, which
  the lookups find, unaligned meta data, part sizes that overflow and
  signature sizes larger than the signature field. The payload hash and
  transport decoding did not validate the header. Lookups of id 0 found
  empty slots.
- bspatch computed offsets that overflow `off_t` from large lengths in a
  patch, such patches fail with `BPAK_SIZE_ERROR`.
- Transport decoding wrote past the part that it decoded and read past the
  origin part when the patch, the copied data or the merkle hash tree was
  larger than the part.
- `bpak_calloc`, `bpak_free` and `bpak_transport_encode` were declared in
  the public headers but not exported by the shared library.
- With an allocator from `bpak_set_calloc_free`, the lzma encoder and
  decoder freed memory from `malloc` with it. The lzma decoder may use at
  most 64 MiB (`BPAK_BSPATCH_LZMA_MEMLIMIT`), it had no limit.
- `bpak_pkg_add_key` and the python package freed keys with `free` instead
  of `bpak_free`.
- `bpak_meta_to_string` did not terminate a `bpak-version` that filled the
  buffer, left the buffer uninitialized when it was too small for a hash and
  read the values of known meta data regardless of their size. `bpak show`
  prints `<invalid>` for values that are too small for their type.
- Transport decoding compares the merkle root hash of a generated hash tree
  with `merkle-root-hash` and fails with `BPAK_BAD_ROOT_HASH`, and the sizes
  of the merkle salt and root hash are checked. `bpak transport --decode`
  printed the offset of the merkle tree.
- `bpak_merkle_init` rejected data of 8 GiB to 1 TiB, which
  `bpak_merkle_compute_size` accepts, so adding such a file with
  `--encoder merkle` crashed. Earlier versions can not verify these
  packages. `bpak_merkle_write_chunk` wrote past the hash tree when it got
  more data than the tree was created for, it fails with `BPAK_SIZE_ERROR`.
- Every package created with `--encoder merkle` had the same merkle salt,
  it came from `random()`, which was never seeded.
- Transport decoding leaked the lzma decoder when a patch failed in the
  middle of a part, `bpak_transport_decode_free` frees it now.
- Adding a part: a file that could not be read, for example a directory,
  or that changed size made `bpak_pkg_add_file` loop forever, a part added
  after a transport encoded part was written at the wrong offset, and a
  failed add left the part in the package. `bpak add --encoder merkle`
  computed the hash tree from the file instead of the added data, which
  overflowed a buffer when the file grew.
- Deleting a part looped forever when the file had data after the last part
  or ended before it, moved the offsets of the following parts by the
  transport size of a transport encoded part, and left the in-memory
  header changed when it failed. A failed `bpak_pkg_open` left the closed
  file in the package, and `filename` was never set.
- `BPAK_DECLARE_STATIC_KEY` stored the key in a byte array, which is not
  aligned for `struct bpak_key`.
- The mbedtls backend ignored the results of the hash functions and of
  parsing key files, did not check an allocation when it loaded a public
  key, leaked the key when verification could not parse it and left the
  private key in a stack buffer.
- `bpak_pkg_sign` signed directly into the header, a failure left it with a
  cleared signature, and the private key was not cleared before it was
  freed. It sets the signature kind of the header to the kind of the key,
  which was not checked.
- `bpak_keystore_load_key_from_file` verifies the payload hash of the
  keystore and fails with `BPAK_BAD_PAYLOAD_HASH` when it is corrupted, it
  read `keystore-provider-id` regardless of its size, and returns
  `BPAK_KEY_NOT_FOUND` instead of `BPAK_NOT_FOUND` when the keystore does
  not contain the key. `bpak verify --keystore` exits with the code of
  `BPAK_KEY_NOT_FOUND` (228) for an unknown key instead of 254.
- File offsets were passed to `fseek` as `long`, packages larger than 2 GiB
  did not work on targets with a 32-bit `long`. Programs that are compiled
  with another size of `off_t` than the library fail to compile, see
  [the C library](docs/c-library.md), and `bpak/bpak.h` compiles with
  `-std=c99`.
- The static library defined the functions of heatshrink and sais without a
  prefix, which clashed with programs that use heatshrink themselves.
- `bpak_pkg_size` and `bpak_pkg_installed_size` wrapped around when the size
  does not fit `size_t`, they return `SIZE_MAX`.
- `bpak_pkg_transport_decode` and `bpak.transport_decode` cleared the
  transport flags in the header of the input package instead of the output
  package, so the input package reported the wrong sizes, and the output
  package kept the header it was opened with until it was opened again.
- bsdiff truncated the length of matches to 32 bits, a match longer than
  2 GiB made `bpak transport --encode` scan backwards.
- `bpak_pkg_delete_part`, and with it `bpak delete --part` and
  `Package.delete_part`, left the `<part>-hash-tree` part of a part added
  with a merkle hash tree in the package. It deletes the hash tree part as
  well.
- `bpak_transport_encode`, and with it `bpak transport --encode --origin`,
  crashed when the origin or the input package had no `bpak-package` meta
  data, and read past a `bpak-package` that is smaller than a UUID. It fails
  with `BPAK_NOT_FOUND` and `BPAK_SIZE_ERROR` like transport decoding.
- Log messages of the library used printf formats that do not match their
  arguments, they printed wrong values, for example in 32-bit builds.
- The public headers were not installed when the library is built as a
  CMake subproject with `add_subdirectory`.
- `bpak/key.h` did not compile unless `bpak/bpak.h` was included first.
- `bpak_transport_encode` returned -1 instead of an error code when a seek
  or the header write failed and for an unknown encoder, which is
  `BPAK_NOT_SUPPORTED` now: `bpak transport --encode` exits with 249 instead
  of 255 for an encoder that `bpak transport --add` added but that does not
  exist.
- Python package: crashes when opening a file that is not a package, when
  using a closed package and after the log callback was released, reference
  leaks in `Package.parts` and `Package.meta`, meta data larger than the
  meta data area overflowed the header, empty parts could not be read, and
  short reads, errors in the log function and failed header writes when
  clearing the signature were not reported.
- `bpak` tool: `delete --all --part`, file errors printed a traceback, file
  names that are not UTF-8.
- Python package: deleting an int attribute, for example `del pkg.key_id`,
  crashed, and values that do not fit the field were truncated,
  `pkg.hash_kind = 256` stored 0. Such values raise `OverflowError` and
  deleting an attribute raises `TypeError`.
- Python package: `Package.sign()` reported argument errors as `verify()`,
  `Meta.as_uuid()` did not check that the `uuid` module has `UUID`, and the
  docstring of `Package.meta` described the parts.
