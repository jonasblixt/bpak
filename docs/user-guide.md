# User guide

This guide builds a firmware package step by step with the `bpak` command
line tool: parts, meta data, a dm-verity hash tree, signing, transport
encoding for updates and keystores. [Package format](format.md) describes the
concepts behind the commands, and the [README](../README.md#installation)
describes how to install the tool.

Every command has a `--help` option, and `bpak --help` lists the commands.

## Creating a package

Create an empty package and add two files as parts:

```
$ bpak create basic.bpak
$ bpak add basic.bpak --part bootloader --from-file bootloader.bin
$ bpak add basic.bpak --part kernel --from-file kernel.bin
$ bpak show basic.bpak
BPAK File: basic.bpak

Hash:        sha256
Signature:   prime256v1
Key ID:      00000000
Keystore ID: 00000000

Metadata:
    ID         Size   Meta ID              Part Ref   Data

Parts:
    ID         Size         Z-pad  Flags          Transport Size
    49b58fc2   98304        0      --------       98304
    ec103b08   307200       0      --------       307200

Header hash:  b2fb80fe2212d5d04d94b16bfbce24bb5e72217d71982417441b36bd5cdf6793
Payload hash: 9802a9080720269ebad173a57b738db67697893657f78aa206919be86b17bb09
```

`show` lists the parts by their ids. The id of a part is computed from its
name, see [IDs](format.md#ids), and `generate id` prints it:

```
$ bpak generate id kernel
id("kernel") = 0xec103b08
```

The package stores only the id, not the name. Every option that takes the
id of a part or of meta data accepts either the name or the id in hex with a
`0x` prefix, so `--part kernel` and `--part 0xec103b08` are the same.

`create` sets the hash algorithm of the package, sha256 by default:

```
$ bpak create demo384.bpak --hash-kind sha384 --signature-kind secp384r1
```

`bpak sign` sets the signature algorithm from the key, so
`--signature-kind` only matters for packages that are signed with an
external tool. `create` asks before it overwrites an existing file, `-Y`
overwrites it without asking.

## Meta data

The following sections build `demo.bpak`, a package with a kernel and a root
file system. Meta data identifies the package and its version:

```
$ bpak create demo.bpak
$ bpak add demo.bpak --meta bpak-package \
                     --from-string 74a53c6d-3556-49f5-a9cd-481ebf22baab \
                     --encoder uuid
$ bpak add demo.bpak --meta bpak-version --from-string 1.1.0
$ bpak add demo.bpak --part kernel --from-file kernel.bin
$ bpak add demo.bpak --meta pb-load-addr --from-string 0x80000000 \
                     --encoder integer --part-ref kernel
$ bpak show demo.bpak
...
Metadata:
    ID         Size   Meta ID              Part Ref   Data
    fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
    9a5bab69   6      bpak-version                    1.1.0
    d1e64a4b   8      pb-load-addr         ec103b08   Entry: 0x80000000
...
```

The `bpak-package` UUID identifies the kind of package, so all versions of
the same firmware use the same UUID. `--part-ref` attaches meta data to a
part, here the load address of the kernel.

`--from-string` gives the value on the command line and `--from-file` reads
it from a file. Without an encoder, a string is stored as it is, followed by
a NUL byte. The encoders store:

| Encoder   | Value                                                       |
|-----------|-------------------------------------------------------------|
| `uuid`    | A UUID, 16 bytes                                            |
| `integer` | A 64 bit integer: decimal, hex with `0x` or octal with `0`  |
| `id`      | The id of a name, 4 bytes                                   |

Show or extract a single value:

```
$ bpak show demo.bpak --meta bpak-version
1.1.0
$ bpak extract demo.bpak --meta bpak-version --output version.bin
```

`set` changes an existing value and takes the same `--encoder` and
`--part-ref` options as `add`. Here the kernel moves to another load
address. `show` selects the part of the meta data with `--part`:

```
$ bpak set demo.bpak --meta pb-load-addr --part-ref kernel \
                     --from-string 0x80008000 --encoder integer
$ bpak show demo.bpak --meta pb-load-addr --part kernel
Entry: 0x80008000
```

## File systems and dm-verity

Add the root file system with a merkle hash tree:

```
$ bpak add demo.bpak --part rootfs --from-file rootfs.img \
                     --set-flag dont-hash --encoder merkle
$ bpak show demo.bpak
...
Metadata:
    ID         Size   Meta ID              Part Ref   Data
    fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
    9a5bab69   6      bpak-version                    1.1.0
    d1e64a4b   8      pb-load-addr         ec103b08   Entry: 0x80008000
    7c9b2f93   32     merkle-salt          979e8728   5300a2a1f1737bbbbc82dfc2bf3648b5fc1d31c58ef2b0e13d30c2eccf545eb2
    e68fc9be   32     merkle-root-hash     979e8728   2b222fc294e69af7b9e10302283f82193063a8ffa59d42a5c389537bf7eb3577

Parts:
    ID         Size         Z-pad  Flags          Transport Size
    ec103b08   307200       0      --------       307200
    979e8728   1048576      0      h-------       1048576
    998ee6de   12288        0      h-------       12288
...
```

The merkle encoder adds a second part, `rootfs-hash-tree` (998ee6de). It
holds a hash tree that is compatible with the dm-verity device mapper target
of the Linux kernel. The salt and the root hash of the tree are stored as
meta data of the `rootfs` part. The salt is random, so it is different every
time a file is added. The size of the file must be a multiple of 4 KiB, the
block size of the tree.

`--set-flag dont-hash` excludes both parts from the payload hash, which `show`
marks with the `h` flag. The root hash is in the signed header, and dm-verity
checks the data when it is read, so the package does not need to hash the
whole file system again when it is verified. `bpak verify` still checks the
hash tree against the data and the root hash.

## Signing and verifying

Set the key id and the keystore id, then sign the package with a private
key:

```
$ bpak set demo.bpak --key-id demo-key --keystore-id demo-keystore
$ bpak sign demo.bpak --key prime256v1-key-pair.pem
$ bpak verify demo.bpak --key prime256v1-public-key.der
Verification OK
```

The key id and the keystore id are optional. A verifier uses them to select
the key, see [Keystores](#keystores). They are part of the signed header, so
set them before the package is signed.

Keys are read in PEM or DER format. Create a key pair with openssl:

```
$ openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-key-pair.pem
$ openssl ec -in prime256v1-key-pair.pem -pubout -outform DER -out prime256v1-public-key.der
```

Any change to a signed package makes the verification fail, and the tool
exits with an error:

```
$ bpak set demo.bpak --meta bpak-version --from-string 1.1.1
$ bpak verify demo.bpak --key prime256v1-public-key.der
Error: verification failed: Verification failed
$ echo $?
236
```

Sign the package again after every change.

## Transport encoding

Updates are usually small changes to large files. Transport encoding replaces
parts with a binary diff against the version that is already installed, the
*origin*. Transport rules in the package select the encoder and the decoder
of each part:

```
$ bpak transport demo.bpak --add --part rootfs \
                           --encoder bsdiff --decoder bspatch
$ bpak transport demo.bpak --add --part rootfs-hash-tree \
                           --encoder remove-data --decoder merkle-generate
$ bpak sign demo.bpak --key prime256v1-key-pair.pem
```

The rules are meta data, so sign the package again after adding them. The
`rootfs` part is sent as a diff. The hash tree is not sent at all, the device
generates it again from the file system and checks it against the signed root
hash. [Transport encoding](format.md#transport-encoding) lists the available
encoders.

Build the previous version, `demo-1.0.0.bpak`, in the same way and with the
same `bpak-package` UUID. Then encode the new version against it:

```
$ bpak transport demo.bpak --encode --origin demo-1.0.0.bpak --output demo-patch.bpak
$ bpak show demo-patch.bpak
...
Parts:
    ID         Size         Z-pad  Flags          Transport Size
    ec103b08   307200       0      --------       307200
    979e8728   1048576      0      hT------       26387
    998ee6de   12288        0      hT------       0
...
```

The `T` flag marks the transport encoded parts. The patch is the header plus
the sum of the *Transport Size* column, 337683 bytes instead of the 1372160
bytes of the package. The kernel did not change, but it is sent in full
because it has no transport rule.

The device decodes the patch with its installed package as the origin:

```
$ bpak transport demo-patch.bpak --decode --origin demo-1.0.0.bpak --output demo-decoded.bpak
$ bpak verify demo-decoded.bpak --key prime256v1-public-key.der
Verification OK
```

The decoded package is identical to `demo.bpak`, including the signature.
The patch itself does not verify, because the transport flags and sizes are
part of its header. A package whose rules only use `merkle-generate` can be
decoded without `--origin`.

## Keystores

A keystore is a package of public keys, one key per part. It lets a device
choose the key that verifies a package from the key id and the keystore id
of the package. The `bpak-package` UUID
`5df103ef-e774-450b-95c5-1fef51ceec28` marks a package as a keystore, and
`keystore-provider-id` is the id that packages refer to with
`--keystore-id`:

```
$ bpak create keystore.bpak
$ bpak add keystore.bpak --meta bpak-package \
                         --from-string 5df103ef-e774-450b-95c5-1fef51ceec28 \
                         --encoder uuid
$ bpak add keystore.bpak --meta keystore-provider-id \
                         --from-string demo-keystore --encoder id
$ bpak add keystore.bpak --part demo-key \
                         --from-file prime256v1-public-key.der --encoder key
$ bpak add keystore.bpak --part backup-key \
                         --from-file secp384r1-public-key.pem --encoder key
$ bpak sign keystore.bpak --key root-key-pair.pem
```

The part names are the key ids. `demo.bpak` was signed with the key id
`demo-key` and the keystore id `demo-keystore`, so the keystore can verify
it:

```
$ bpak verify demo.bpak --keystore keystore.bpak
Verification OK
```

`--keystore` checks that the keystore is intact with its payload hash, but
not its signature. Verify the keystore itself with the root key:

```
$ bpak verify keystore.bpak --key root-public-key.der
Verification OK
```

A device can load a signed keystore at runtime to extend its root of trust.
A keystore can also be built into a bootloader as C code:

```
$ bpak generate keystore keystore.bpak --name demo
/* Automatically generated with bpak 1.0.0 */
#include <bpak/bpak.h>
#include <bpak/keystore.h>


const struct bpak_key keystore_demo_key0 =
{
    .id = 0x5ae3443,
    .size = 91,
    .kind = BPAK_KEY_PUB_PRIME256v1,
    .data =
    {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
            ...
    },
};

const struct bpak_key keystore_demo_key1 =
...

const struct bpak_keystore keystore_demo =
{
    .id = 0xf7fe662a,
    .no_of_keys = 2,
    .verified = true,
    .keys =
    {
        (struct bpak_key *) &keystore_demo_key0,
        (struct bpak_key *) &keystore_demo_key1,
    },
};
```

`--decorate` places the keystore and the keys in the `.keystore_header` and
`.keystore_key` linker sections.

## Signing with an external tool

Release candidates often go through a long test cycle. Once one is approved,
it should be released as it is instead of being built again. The signature
of a package can be replaced without changing anything else, so a release
candidate that was signed with a development key can be signed again with
the production key, for example in a separate signing environment with a
hardware security module.

Set the production key id and keystore id, then write the binary header hash
to a file. This hash is what gets signed:

```
$ bpak set demo.bpak --key-id release-key --keystore-id production-keystore
$ bpak show demo.bpak --binary-hash > hash.bin
```

Sign the hash, here with openssl:

```
$ openssl pkeyutl -sign -inkey release-key-pair.pem -in hash.bin -out signature.der
```

For an RSA key, also give the hash algorithm of the package, for example
`-pkeyopt digest:sha256`. Then write the signature to the package:

```
$ bpak sign demo.bpak --signature signature.der
$ bpak verify demo.bpak --key release-public-key.der
Verification OK
```

## Inspecting and editing packages

Compare two packages:

```
$ bpak compare demo-1.0.0.bpak demo.bpak
BPAK comparison between:
1: 'demo-1.0.0.bpak'
2: 'demo.bpak'

=   : No difference
+   : Exists in file 2 but not in file 1
-   : Exists in file 1 but not in file 2
*   : Exists in both but data differs

Metadata:
    ID         Size   Meta ID              Data
=   fb2f1f3f   16     bpak-package         74a53c6d-3556-49f5-a9cd-481ebf22baab
*   9a5bab69   6      bpak-version         1.0.0
=   d1e64a4b   8      pb-load-addr         Entry: 0x80008000
*   7c9b2f93   32     merkle-salt          887edf5a8a2f019f81aa0739c424cc65b0991231175dc2429961da8fd1d4ce7e
*   e68fc9be   32     merkle-root-hash     8105f54a5dcf1a50d70385c26485e22cd6e196ee6bba640dee5c5af45781e35a
=   2d44bbfb   32     bpak-transport       Encode: 9f7aacf9, Decode: b5964388
=   2d44bbfb   32     bpak-transport       Encode: 57004cd0, Decode: b5bcc58f

Parts:
    ID         Size         Z-pad  Flags          Transport Size
=   ec103b08   307200       0      --------       307200
*   979e8728   1048576      0      h-------       1048576
*   998ee6de   12288        0      h-------       12288
```

The data column shows the values of the first package.

Other commands:

| Command                                                        | Description                                  |
|----------------------------------------------------------------|----------------------------------------------|
| `bpak show demo.bpak --hash`                                   | Print the header hash                        |
| `bpak show demo.bpak --part kernel`                            | Print the size of a part                     |
| `bpak show demo.bpak --part-hash kernel`                       | Print the SHA-256 hash of a part             |
| `bpak extract demo.bpak --part kernel -o k.bin`                | Write the data of a part to a file           |
| `bpak extract demo.bpak --meta pb-load-addr --part-ref kernel` | Write the value of meta data to stdout       |
| `bpak delete demo.bpak --part kernel`                          | Delete a part and its meta data              |
| `bpak delete demo.bpak --all`                                  | Delete all parts                             |

`delete` also deletes the meta data of the deleted parts, unless
`--keep-meta` is given. Deleting a part with a merkle hash tree also deletes
its `<part>-hash-tree` part.

## Verbose output and errors

`-v` prints more details, and repeating it prints even more:
`bpak show demo.bpak -vv`. The option can be given before or after the
command.

Errors are printed on stderr. The exit code is 2 for invalid options, and
otherwise the negated error code of the library, `enum bpak_errors` in
[`include/bpak/bpak.h`](../include/bpak/bpak.h), as an unsigned byte. For
example, a failed verification (`BPAK_VERIFY_FAIL`, 20) exits with 236.
Errors reading or writing other files, like the `--output` of `extract`, exit
with 255 (`BPAK_FAILED`).

## Shell completion

`bpak completion` prints how to enable shell completion for bash, zsh and
fish. For bash, add this line to `~/.bashrc`:

```
eval "$(_BPAK_COMPLETE=bash_source bpak)"
```
