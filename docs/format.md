# Package format

A bpak package is a 4 KiB header followed by the data of its parts:

```
+---------------------------+  0
| header (4096 bytes)       |
+---------------------------+  4096
| part 1 data + padding     |
+---------------------------+
| part 2 data + padding     |
+---------------------------+
| ...                       |
+---------------------------+
```

The header describes the parts and holds the meta data, the payload hash and
the signature. Everything that is needed to verify a package is in the
header, so a bootloader can read and verify the header first and then
process the parts one at a time.

All integers are stored in little endian byte order. The format is defined
by `struct bpak_header` in [`include/bpak/bpak.h`](../include/bpak/bpak.h)
and never changes in an incompatible way: new versions keep reading packages
that old versions created, and old versions read packages that new versions
create.

## IDs

Parts, meta data, keys, keystores and transport algorithms are identified by
32 bit ids. `bpak_id()` computes the id of a name with a CRC32 (the reflected
polynomial 0xEDB88320) without the initial and final XOR:

```
bpak_id("bpak-package") = 0xfb2f1f3f
bpak_id("kernel")       = 0xec103b08
```

A package stores only the ids, not the names. The `bpak` tool accepts a name
wherever an id is expected and translates it, or an id in hex with a `0x`
prefix. `bpak generate id <name>` prints the id of a name.

## Header

| Offset | Size | Field            | Description                                          |
|-------:|-----:|------------------|------------------------------------------------------|
| 0      | 4    | `magic`          | `0x42504132` (`BPAK_HEADER_MAGIC`)                   |
| 4      | 4    |                  | Zero                                                 |
| 8      | 512  | `meta`           | 32 meta data headers of 16 bytes                     |
| 520    | 1024 | `parts`          | 32 part headers of 32 bytes                          |
| 1544   | 1920 | `metadata`       | The values of the meta data                          |
| 3464   | 1    | `hash_kind`      | `enum bpak_hash_kind`: sha256, sha384 or sha512      |
| 3465   | 1    | `signature_kind` | `enum bpak_signature_kind`                           |
| 3466   | 2    | `alignment`      | Part alignment, 512                                  |
| 3468   | 64   | `payload_hash`   | Hash of the part data                                |
| 3532   | 4    | `key_id`         | Id of the key that signed the package                |
| 3536   | 4    | `keystore_id`    | Id of the keystore that holds the key                |
| 3540   | 42   |                  | Zero                                                 |
| 3582   | 512  | `signature`      | The signature, DER encoded for ECDSA                 |
| 4094   | 2    | `signature_sz`   | Size of the signature                                |

Unused entries in the `meta` and `parts` arrays have the id 0, so a package
holds at most 32 parts and 32 meta data entries. The used entries come
first: the first entry with the id 0 ends the array, and
`bpak_valid_header()` rejects headers with used entries after it.

## Parts

A part is a block of data, for example a kernel, a device tree or a file
system image. Part data is zero padded to a multiple of 512 bytes and stored
in the order of the part headers, so the offset of a part is the size of the
header plus the padded sizes of the parts before it.

| Offset | Size | Field            | Description                                          |
|-------:|-----:|------------------|------------------------------------------------------|
| 0      | 4    | `id`             | Id of the part                                       |
| 4      | 8    | `size`           | Size of the data, without padding                    |
| 12     | 8    | `offset`         | Offset of the data in the package, informational     |
| 20     | 8    | `transport_size` | Size of the transport encoded data                   |
| 28     | 2    | `pad_bytes`      | Number of zero bytes after the data                  |
| 30     | 1    | `flags`          | See below                                            |
| 31     | 1    |                  | Zero                                                 |

Flags:

| Flag                          | `bpak show` | Description                                    |
|-------------------------------|-------------|------------------------------------------------|
| `BPAK_FLAG_EXCLUDE_FROM_HASH` | `h`         | The part is not included in the payload hash   |
| `BPAK_FLAG_TRANSPORT`         | `T`         | The part data is transport encoded             |

A part that is excluded from the payload hash must be protected in another
way, typically with a merkle hash tree whose root hash is stored as meta
data.

## Meta data

Meta data are small values in the header, at most 1920 bytes in total. An
entry has an id, a size and an optional reference to the part that it
belongs to. Several entries can have the same id when they refer to
different parts.

| Offset | Size | Field            | Description                                          |
|-------:|-----:|------------------|------------------------------------------------------|
| 0      | 4    | `id`             | Id of the meta data                                  |
| 4      | 2    | `size`           | Size of the value                                    |
| 6      | 2    | `offset`         | Offset of the value in `metadata`, a multiple of 8   |
| 8      | 4    | `part_id_ref`    | Id of the part that the meta data belongs to, or 0   |
| 12     | 4    |                  | Zero                                                 |

The library knows these meta data ids:

| Name                   | ID         | Value                                                      |
|------------------------|------------|------------------------------------------------------------|
| `bpak-package`         | 0xfb2f1f3f | UUID (16 bytes) that identifies the kind of package        |
| `bpak-version`         | 0x9a5bab69 | Version string, NUL terminated                             |
| `bpak-transport`       | 0x2d44bbfb | Transport encoder and decoder of a part, see below         |
| `merkle-salt`          | 0x7c9b2f93 | Salt of the merkle hash tree of a part (32 bytes)          |
| `merkle-root-hash`     | 0xe68fc9be | Root hash of the merkle hash tree of a part (32 bytes)     |
| `keystore-provider-id` | 0xfb367d9a | Id of a keystore (4 bytes), see [Keystores](#keystores)    |
| `pb-load-addr`         | 0xd1e64a4b | Load address of a part (64 bit integer), used by punchboot |

Applications can add their own meta data with any other id. All versions of
the same kind of package should use the same `bpak-package` UUID, because
transport decoding checks that the origin package has the same UUID as the
patch.

## Hashing and signing

The *payload hash* is computed over the data and padding of all parts that
do not have the `BPAK_FLAG_EXCLUDE_FROM_HASH` flag, in the order of the
parts, and is stored in the header.

The *header hash* is computed over the header with the signature and the
signature size replaced by zeros. Because the header contains the payload
hash, the header hash covers the entire package, and the signature is a
signature of the header hash.

The hash algorithm is sha256, sha384 or sha512 and is selected when the
package is created. The signature algorithm is ECDSA with prime256v1 (NIST
P-256), secp384r1 or secp521r1, or RSA 4096 with PKCS#1 v1.5 padding. It is
determined by the key: `bpak sign` sets `signature_kind` to the kind of its
key, and verification uses the kind of the verification key, not
`signature_kind`.

The signature is computed over the binary header hash. ECDSA signatures are
stored DER encoded, which is what `openssl pkeyutl -sign` produces, for
example. This means that a package can be signed outside of bpak, for
example with a hardware security module, see
[Signing with an external tool](user-guide.md#signing-with-an-external-tool).

Verification checks the signature of the header hash, computes the payload
hash again and, for parts with a merkle hash tree, computes the tree again
and compares it and its root hash with the stored ones.

The `key_id` and `keystore_id` fields tell the verifier which key to use.
They are part of the signed header, but the signature algorithm does not use
them.

## Merkle hash trees

A part can be followed by a merkle hash tree of its data. The tree is stored
in a separate part with the id of `<part name>-hash-tree`, and the salt and
the root hash are stored as `merkle-salt` and `merkle-root-hash` meta data
that refer to the data part. The tree uses 4 KiB blocks and sha256, is
compatible with the dm-verity device mapper target of the Linux kernel and
is a multiple of 4 KiB, so the tree part has no padding. The size of the
data part must be a multiple of 4 KiB as well. The salt is 32 random bytes.

File system images that are mounted with dm-verity are typically excluded
from the payload hash: the root hash is part of the signed header, and
dm-verity checks the data when it is read.

## Transport encoding

To make updates smaller, parts can be *transport encoded*. The
`bpak-transport` meta data of a part names the encoder that is used when a
package is encoded and the decoder that restores the part when it is
installed:

```c
struct bpak_transport_meta {
    uint32_t alg_id_encode;
    uint32_t alg_id_decode;
    uint8_t data[24];
};
```

| Encoder (id)                | Decoder (id)                 | Description                                              |
|-----------------------------|------------------------------|----------------------------------------------------------|
| `bsdiff` (9f7aacf9)         | `bspatch` (b5964388)         | Binary diff against the same part in an origin package, heatshrink compressed |
| `bsdiff-lzma` (1607e56e)    | `bspatch-lzma` (933a9893)    | As above, LZMA compressed                                |
| `bsdiff-no-comp` (0a878e3e) | `bspatch-no-comp` (75622592) | As above, not compressed                                 |
| `remove-data` (57004cd0)    | `merkle-generate` (b5bcc58f) | The merkle hash tree is removed and generated again from the part data |

Parts without transport meta data are copied as they are. An encoded part
has the `BPAK_FLAG_TRANSPORT` flag and its encoded size in
`transport_size`.

The diff based decoders need the *origin* package, the version that is
already installed. Decoding a patch restores the original package exactly,
including the header and the signature, so the decoded package verifies
with the same key. The encoded package itself does not verify, because its
header has the transport flags and sizes set.

The decoder checks that the patch only writes within its parts, that it only
reads the same part of the origin and that a generated hash tree has the
signed root hash. Everything else in a patch is unauthenticated until the
decoded package is verified.

## Keystores

A keystore is a package that carries public keys, one DER encoded key per
part. It is identified by:

- the `bpak-package` UUID `5df103ef-e774-450b-95c5-1fef51ceec28`, which is
  reserved for keystores
- a `keystore-provider-id` meta data entry with the id of the keystore

A package that is signed with a key from a keystore has the id of the
keystore in `keystore_id` and the part id of the key in `key_id`. A keystore
can itself be signed, which allows a device to extend its root of trust with
keys that it loads at runtime. Loading a key from a keystore file checks the
payload hash of the keystore but not its signature, so verify the keystore
with its own key first. `bpak generate keystore` turns a keystore into C code
that can be built into a bootloader.
