# Changelog

Changes that affect users of the library, the python package and the `bpak`
tool. The package format and the library ABI stay compatible, see
[Compatibility](docs/development.md#compatibility).

## 1.0.0 (unreleased)

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
- Python package: crashes when opening a file that is not a package, when
  using a closed package and after the log callback was released, reference
  leaks in `Package.parts` and `Package.meta`, meta data larger than the
  meta data area overflowed the header, empty parts could not be read, and
  short reads, errors in the log function and failed header writes when
  clearing the signature were not reported.
- `bpak` tool: `delete --all --part`, file errors printed a traceback, file
  names that are not UTF-8.
