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
the signature. Everything that is needed to verify a package is in the header,
so a bootloader can read and verify the header first and then process the
parts one at a time.

All integers are stored in little endian byte order. The format is defined by
`struct bpak_header` in [`include/bpak/bpak.h`](../include/bpak/bpak.h) and
never changes in an incompatible way: packages created by old versions keep
working with new versions and the other way around.

## IDs

Parts, meta data, keys, keystores and transport algorithms are identified by
32 bit ids. An id is computed from a name with `bpak_id()`, a CRC32 (the
reflected polynomial 0xEDB88320) without the initial and final XOR:

```
bpak_id("bpak-package") = 0xfb2f1f3f
bpak_id("kernel")       = 0xec103b08
```

The `bpak` tool accepts names wherever an id is expected and translates them,
or ids written as hex with a `0x` prefix. `bpak generate id <name>` prints the
id of a name. Only the id is stored in the package, the name is not.

## Header

| Offset | Size | Field            | Description                                          |
|-------:|-----:|------------------|------------------------------------------------------|
| 0      | 4    | `magic`          | `0x42504132` (`BPAK_HEADER_MAGIC`)                   |
| 8      | 512  | `meta`           | 32 meta data headers of 16 bytes                     |
| 520    | 1024 | `parts`          | 32 part headers of 32 bytes                          |
| 1544   | 1920 | `metadata`       | Storage for the meta data values                     |
| 3464   | 1    | `hash_kind`      | `enum bpak_hash_kind`: sha256, sha384 or sha512      |
| 3465   | 1    | `signature_kind` | `enum bpak_signature_kind`                           |
| 3466   | 2    | `alignment`      | Part alignment, 512                                  |
| 3468   | 64   | `payload_hash`   | Hash of the part data                                |
| 3532   | 4    | `key_id`         | Id of the key that signed the package                |
| 3536   | 4    | `keystore_id`    | Id of the keystore that holds the key                |
| 3582   | 512  | `signature`      | DER encoded signature                                |
| 4094   | 2    | `signature_sz`   | Size of the signature                                |

Unused entries in the `meta` and `parts` arrays have the id 0, so a package
holds at most 32 parts and 32 meta data entries.

## Parts

A part is a block of data, for example a kernel, a device tree or a file
system image. The part header holds the id, the size, the offset of the data
in the package, flags and the number of padding bytes. Part data is zero
padded to a multiple of 512 bytes and stored in the order of the part
headers.

Flags:

| Flag                          | `bpak show` | Description                                    |
|-------------------------------|-------------|------------------------------------------------|
| `BPAK_FLAG_EXCLUDE_FROM_HASH` | `h`         | The part is not included in the payload hash   |
| `BPAK_FLAG_TRANSPORT`         | `T`         | The part data is transport encoded             |

Parts that are excluded from the payload hash must be protected in some other
way, typically with a merkle hash tree whose root hash is stored as meta data.

## Meta data

Meta data are small values in the header, at most 1920 bytes in total. An
entry has an id, a size and an optional reference to the part that it belongs
to. Several entries can have the same id when they refer to different parts.

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

Applications can add their own meta data with any other id. Packages of the
same kind should use the same `bpak-package` UUID, transport decoding checks
that the origin package has the same UUID as the patch.

## Hashing and signing

The *payload hash* is computed over the data and padding of all parts that do
not have the `BPAK_FLAG_EXCLUDE_FROM_HASH` flag and is stored in the header.

The *header hash* is computed over the header with the signature and the
signature size replaced by zeros. Because the header contains the payload hash,
the header hash covers the entire package, and the signature is a signature of
the header hash.

The hash algorithm is sha256, sha384 or sha512 and the signature algorithm
ECDSA with prime256v1 (NIST P-256), secp384r1 or secp521r1, or RSA 4096
(PKCS#1 v1.5). Both are selected when a package is created.

The signature is computed over the binary header hash. ECDSA signatures are
stored DER encoded, which is what for example `openssl pkeyutl -sign`
produces. This means that a package can be signed outside of bpak, for
example with a hardware security module, see
[Signing with an external tool](user-guide.md#signing-with-an-external-tool).

Verification checks the signature of the header hash, recomputes the payload
hash and, for parts with a merkle hash tree, recomputes the tree and compares
it and its root hash with the stored ones.

The `key_id` and `keystore_id` fields tell the verifier which key to use. They
are part of the signed header but are not used by the signature algorithm
itself.

## Merkle hash trees

A part can be followed by a merkle hash tree of its data. The tree is stored
in a separate part with the id of `<part name>-hash-tree`, and the salt and
the root hash are stored as `merkle-salt` and `merkle-root-hash` meta data
that refer to the data part. The tree uses 4 KiB blocks and sha256 and is
compatible with the dm-verity device mapper target of the Linux kernel.

File system images that are mounted with dm-verity are typically excluded from
the payload hash: the root hash is part of the signed header and dm-verity
checks the data when it is read.

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

| Encoder          | Decoder           | Description                                              |
|------------------|-------------------|----------------------------------------------------------|
| `bsdiff`         | `bspatch`         | Binary diff against the same part in an origin package, heatshrink compressed |
| `bsdiff-lzma`    | `bspatch-lzma`    | As above, LZMA compressed                                |
| `bsdiff-no-comp` | `bspatch-no-comp` | As above, not compressed                                 |
| `remove-data`    | `merkle-generate` | The merkle hash tree is removed and generated again from the part data |

Parts without transport meta data are copied as they are. An encoded part has
the `BPAK_FLAG_TRANSPORT` flag and its encoded size in `transport_size`.

The diff based decoders need the *origin* package, the version that is
already installed. Decoding a patch restores the original package exactly,
including the header and the signature, so the decoded package verifies with
the same key. The encoded package itself does not verify, because its header
has the transport flags and sizes set.

## Keystores

A keystore is a package that carries public keys, one key per part, DER
encoded. It is identified by:

- the `bpak-package` UUID `5df103ef-e774-450b-95c5-1fef51ceec28`, which is
  reserved for keystores
- a `keystore-provider-id` meta data entry with the id of the keystore

A package that is signed with a key from a keystore has the id of the
keystore in `keystore_id` and the part id of the key in `key_id`. A keystore
can itself be signed, which allows a device to extend its root of trust with
keys that are loaded at runtime. `bpak generate keystore` turns a keystore
into C code that can be built into a bootloader.
