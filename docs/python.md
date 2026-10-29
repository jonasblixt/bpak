# Python package

The `bpak` python package wraps the C library and contains the `bpak`
command line tool. It requires Python 3.10 or later.

## Installation

Install the package from the repository root with pip, or add it to a
[uv](https://docs.astral.sh/uv) project:

```
$ pip install .
$ uv add /path/to/bpak
```

The package is built from source with CMake and includes the library, so the
build needs a C compiler and the mbedtls and liblzma development packages,
for example `libmbedtls-dev` and `liblzma-dev` on Debian and Ubuntu.

## Example

```python
import uuid

import bpak

with bpak.Package("demo.bpak", "wb+") as pkg:
    pkg.hash_kind = bpak.HASH_SHA256
    pkg.add_meta(bpak.id("bpak-package"),
                 data=uuid.UUID("74a53c6d-3556-49f5-a9cd-481ebf22baab").bytes)
    pkg.add_meta(bpak.id("bpak-version"), data="1.1.0")
    pkg.add_file("kernel", "kernel.bin")
    pkg.add_file("rootfs", "rootfs.img", with_merkle_tree=True,
                 flags=bpak.FLAG_EXCLUDE_FROM_HASH)
    pkg.key_id = bpak.id("demo-key")
    pkg.keystore_id = bpak.id("demo-keystore")
    pkg.sign("prime256v1-key-pair.pem")

with bpak.Package("demo.bpak", "rb") as pkg:
    pkg.verify("prime256v1-public-key.der")
    print(pkg.get_meta(bpak.id("bpak-version")).as_string())
    for part in pkg.parts:
        print(f"{part.id:08x} {part.installed_size}")
```

[`examples/python/package.py`](../examples/python/package.py) also transport
encodes and decodes a package.

## API

The type stub [`bpak/_bpak.pyi`](../tools/bpak/_bpak.pyi) lists the complete
API with types.

### Functions

| Function                                   | Description                                         |
|--------------------------------------------|-----------------------------------------------------|
| `id(name)`                                 | The id of a name, see [IDs](format.md#ids)          |
| `id_to_string(id)`                         | The name of a known meta data id, or `""`           |
| `transport_encode(input, output, origin)`  | Transport encode `input` into `output`, with diffs against `origin` |
| `transport_decode(input, output, origin)`  | Decode the transport encoded `input` into `output`, `origin` is the installed version |
| `parse_public_key(data)`                   | Parse a DER encoded public key, returns `(KEY_* kind, DER data)` |
| `hash_kind_to_string(kind)`, `signature_kind_to_string(kind)` | Names of the `HASH_*` and `SIGN_*` constants |
| `set_log_func(func)`                       | Receive the log messages of the library as `func(level, message)`, `None` disables logging |
| `version()`                                | Version of the library                              |

`origin` can be left out when no part uses a diff based encoder. After
`transport_encode` and `transport_decode`, `output` describes the encoded or
decoded package, and `input` is unchanged.

Constants:

| Constant                                   | Description                                         |
|--------------------------------------------|-----------------------------------------------------|
| `HASH_SHA256`, `HASH_SHA384`, `HASH_SHA512` | Hash algorithms, `Package.hash_kind`               |
| `SIGN_PRIME256v1`, `SIGN_SECP384r1`, `SIGN_SECP521r1`, `SIGN_RSA4096` | Signature algorithms, `Package.signature_kind` |
| `KEY_PUB_PRIME256v1`, `KEY_PUB_SECP384r1`, `KEY_PUB_SECP521r1`, `KEY_PUB_RSA4096` | Kinds of public keys, from `parse_public_key` |
| `FLAG_EXCLUDE_FROM_HASH`, `FLAG_TRANSPORT` | Part flags, `Part.flags`                            |
| `METADATA_BYTES`, `SIGNATURE_MAX_BYTES`    | Size of the meta data storage and of the signature field |

### Package

`Package(filename, mode)` opens a package. `mode` is a `fopen()` mode: `"rb"`
to read, `"rb+"` to modify an existing package and `"wb+"` to create a new
one. A package is a context manager and is closed at the end of the `with`
block, or with `close()`. Changes are written to the file when they are
made. Once the package is closed, operations that read or write the file
raise `ValueError`, also through its parts and meta data.

| Attribute                     | Description                                           |
|-------------------------------|-------------------------------------------------------|
| `hash_kind`, `signature_kind` | Algorithms, `HASH_*` and `SIGN_*` constants. `sign()` sets `signature_kind` from the key |
| `key_id`, `keystore_id`       | Ids that select the verification key                  |
| `parts`, `meta`               | Lists of `Part` and `Meta` objects                    |
| `signature`                   | The signature, can be set to a signature created elsewhere or to `None` to clear it |
| `digest`                      | The header hash                                       |
| `payload_hash`                | The payload hash stored in the header                 |
| `size`                        | Size of the package file, with transport encoded parts at their encoded size |
| `installed_size`              | Size of the part data when it is installed            |

| Method                                                 | Description                                  |
|--------------------------------------------------------|----------------------------------------------|
| `add_file(part_name, filename, with_merkle_tree=False, flags=0)` | Add a file as a part, optionally followed by a `<part_name>-hash-tree` part |
| `add_key(part_name, filename, flags=0)`                | Add a PEM or DER encoded public key as a DER encoded part, for keystores |
| `add_meta(id, part_id_ref=0, data=None, size=-1)`      | Add meta data from bytes or a string, or `size` zero bytes |
| `add_transport_meta(part_id, encoder_id, decoder_id)`  | Add a transport rule for a part              |
| `get_part(id)`, `get_meta(id, part_id_ref=0)`          | Find a part or meta data, raise `KeyError` if it does not exist |
| `delete_part(id, remove_meta=True)`, `delete_all_parts(remove_meta=True)` | Delete parts, their `<name>-hash-tree` parts and their meta data |
| `extract_file(id, filename)`                           | Write the data of a part to a file           |
| `part_sha256(id)`                                      | SHA-256 hash of the data of a part           |
| `sign(sign_key_path)`                                  | Update the payload hash and sign the package |
| `verify(verify_key_path)`, `verify(keystore_path=...)` | Verify the signature and the payload with a public key or with a key from a keystore, returns `True` or raises an exception |
| `update_hash()`                                        | Update the payload hash and return the header hash |
| `write_header()`                                       | Write the header to the file                 |

`verify(keystore_path=...)` checks the payload hash of the keystore but not
its signature, see [Keystores](format.md#keystores).

### Part and Meta

`Part` has the read-only attributes `id`, `size`, `installed_size`,
`transport_size`, `pad_bytes`, `flags`, `offset` and
`is_transport_encoded`, and the methods `read_data()` and
`delete(remove_meta=True)`.

`Meta` has the read-only attributes `id`, `part_id_ref` and `size`, the
attribute `raw_data` and the methods `as_uuid()`, `as_string()`,
`describe()` and `delete()`. Setting `raw_data` changes the value, and
strings are stored with a terminating NUL.

### Errors

Errors of the library raise exceptions derived from `bpak.Error`, one for
each value of `enum bpak_errors`, for example `bpak.VerifyFailError`. The
class attribute `code` holds the error code:

```python
try:
    pkg.verify("prime256v1-public-key.der")
except bpak.VerifyFailError:
    print("The signature does not match")
except bpak.Error as e:
    print(f"Verification failed: {e} ({e.code})")
```
