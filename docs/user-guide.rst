User guide
==========

-------------
Basic example
-------------

In the simplest use-case for bitpacker the archive can be viewed as a container
format for other binaries with metadata on sizes and offsets of the parts it 
contains.

Create an empty archive::

    $ bpak create demo.bpak
    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1

    Metadata:
        ID         Size   Meta ID              Part Ref   Data

    Parts:
        ID         Size         Z-pad  Flags          Transport Size

    Hash: b4ea1989f2e8a8be290bf819644e41fcc9631b62ab0c21b6355e3cfd50fb44eb

Add two parts to the archive::

    $ bpak add demo.bpak --part part1 --from-file file_one
    $ bpak add demo.bpak --part part2 --from-file file_two
    $ bpak show demo.bpak

    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1

    Metadata:
        ID         Size   Meta ID              Part Ref   Data

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        37b0705f   4857856      0      --------       4857856
        aeb921e5   4907008      0      --------       4907008

    Hash: c41a2bf1096628f9d81d2e52318e591a7519182e2c17ab0d0f3790c63f656a5c

The archive now contains the two files and some metadata that describes how
the files are stored in the archive. 


----------------
Advanced example
----------------

Create an empty archive::

    $ bpak create demo.bpak
    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1
    Key ID:      00000000
    Keystore ID: 00000000

    Metadata:
        ID         Size   Meta ID              Part Ref   Data

    Parts:
        ID         Size         Z-pad  Flags          Transport Size

    Hash: b4ea1989f2e8a8be290bf819644e41fcc9631b62ab0c21b6355e3cfd50fb44eb

The default hashing and signing algorithm is sha256 and elliptic curve prime256v1
signature format.

Adding a package type identifier::

    $ bpak add demo.bpak --meta bpak-package \
                         --from-string "74a53c6d-3556-49f5-a9cd-481ebf22baab" \
                         --encoder uuid

    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1
    Key ID:      00000000
    Keystore ID: 00000000

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab

    Parts:
        ID         Size         Z-pad  Flags          Transport Size

    Hash: 0e6e976e6137b1e8e38546773c9e257495053fd42d397e0f958cdd39786cddca

Bitpacker supports a few ways to encode metadata, in the example above we're
using the uuid encoder to translate the uuid string into the 16 byte 'raw' uuid.

Adding some real data::

    $ bpak add demo.bpak --part fs \
                         --from-file demo_filesystem.squash \
                         --set-flag dont-hash \
                         --encoder merkle
    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1
    Key ID:      00000000
    Keystore ID: 00000000

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
        7c9b2f93   32     merkle-salt          faabeca7   92c1b824ade773441e2f57698dc6bb6937f2ed14b9deea702c8520319c79b829
        e68fc9be   32     merkle-root-hash     faabeca7   89acacdf13051c2f5058c13453f7f812fd25164a09e4a0cae30d8c4bb846f81d

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   4857856      0      h-------       4857856
        77fadb17   45056        0      h-------       45056

    Hash: aa6bdefc5e1a95dcfe6211fbbc6d1a68984d99c2c4fa9d0ed074c4f520b40046
 
In this operation we added a squashfs filesystem image with the merkle encoder.
This creates an additional part that contains a merkle hash tree, which is
compatible with the dm-verity device mapper target in the linux kernel.

Another result of the merkle encoder are two additional metadata fields,
the 'merkle-root-hash' and the 'merkle-salt'. The root hash meta as the name
suggests is the top most hash in the hash tree.

In this archive the parts are not hashed because we only need to ensure that
the salt and root hash are not compromised.

Add transport encoding information::

    $ bpak transport demo.bpak --add --part fs \
                               --encoder bsdiff \
                               --decoder bspatch

    $ bpak transport demo.bpak --add --part fs-hash-tree \
                               --encoder remove-data \
                               --decoder merkle-generate
    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
        7c9b2f93   32     merkle-salt          faabeca7   92c1b824ade773441e2f57698dc6bb6937f2ed14b9deea702c8520319c79b829
        e68fc9be   32     merkle-root-hash     faabeca7   89acacdf13051c2f5058c13453f7f812fd25164a09e4a0cae30d8c4bb846f81d
        2d44bbfb   32     bpak-transport       faabeca7   Encode: 9f7aacf9, Decode: b5964388
        2d44bbfb   32     bpak-transport       77fadb17   Encode: 57004cd0, Decode: b5bcc58f

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   4857856      0      h-------       4857856
        77fadb17   45056        0      h-------       45056

    Hash: cadbd6ed13046bc40da6a522ae45df6e48b5d3fea4b124e9ab9c4c7fcad6243f
 
The archive now contains information on how the two parts should be encoded
for transport and how they should be decoded when installing the archive. In
this example the hash-tree is completely removed because it can be generated
using the data in the 'fs' part and the 'merkle-salt' meta, and then be verified
by comparing the 'merkle-root-hash' meta with the generated root hash.

The 'fs' part is encoded using the bsdiff algorithm, which when the actual
encoding is going to be done requires some reference data.

Signing the package::

    $ bpak set demo.bpak --key-id demo-key --keystore-id demo-key-store
    $ bpak sign demo.bpak --key prime256v1-key-pair.pem

    $ bpak show demo.bpak
    BPAK File: demo.bpak

    Hash:      sha256
    Signature: prime256v1
    Key ID:      05ae3443
    Keystore ID: f45573db

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
        7c9b2f93   32     merkle-salt          faabeca7   92c1b824ade773441e2f57698dc6bb6937f2ed14b9deea702c8520319c79b829
        e68fc9be   32     merkle-root-hash     faabeca7   89acacdf13051c2f5058c13453f7f812fd25164a09e4a0cae30d8c4bb846f81d
        2d44bbfb   32     bpak-transport       faabeca7   Encode: 9f7aacf9, Decode: b5964388
        2d44bbfb   32     bpak-transport       77fadb17   Encode: 57004cd0, Decode: b5bcc58f

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   4857856      0      h-------       4857856
        77fadb17   45056        0      h-------       45056
    
    Hash: 86712dfc65614c56d1fcb4fbcb0b2775ce5dacc84cc7c9a8248d2378101b6ee4

Setting the key-id and keystore-id is optional and can be used in the verification
 process to select the correct verification key.

Verifying the package::

    $ bpak verify demo.bpak --key prime256v1-public-key.der
    Verification OK

Encoding the package for transport::

    $ bpak transport demo.bpak --encode --origin demo_old.bpak --output demo_transport.bpak
    $ bpak show demo_transport.bpak
    BPAK File: demo_transport.bpak

    Hash:      sha256
    Signature: prime256v1
    Key ID:      05ae3443
    Keystore ID: f45573db

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    74a53c6d-3556-49f5-a9cd-481ebf22baab
        7c9b2f93   32     merkle-salt          faabeca7   6e23bf2f6fc7c473b68b4a6e48927e1751cf100ff7f1ff4119b23559fb824147
        e68fc9be   32     merkle-root-hash     faabeca7   e26e259011cbf2b7073201f2eeafc7b8ca98512c91a7338b06119c9e137fec9c
        2d44bbfb   32     bpak-transport       77fadb17   Encode: 57004cd0, Decode: b5bcc58f
        2d44bbfb   32     bpak-transport       faabeca7   Encode: 9f7aacf9, Decode: b5964388

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   4907008      0      hT------       114562
        77fadb17   45056        0      hT------       0

    Hash: a649eb0532f848f34116deed81140feb5a1f4a221f964231c83216b6cf8896dd

The demo_transport.bpak is now transport encoded. Note the additional 'T' flag which
indicates that a part is transport encoded. The new archive size is now the
sum of the sizes in the 'Transport Size' column.

---------------
Comparing files
---------------

Compare files::

    $ bpak compare vA.bpak vB.bpak
    BPAK comparison between:
    1: 'vA.bpak'
    2: 'vB.bpak'

    =   : No differance
    +   : Exists in file 2 but not in file 1
    -   : Exists in file 1 but not in file 2
    *   : Exists in both but data differs

    Metadata:
        ID         Size   Meta ID              Data
    =   fb2f1f3f   16     bpak-package         0888b0fa-9c48-4524-9845-06a641b61edd
    *   79c3b7b4   16
    =   2d44bbfb   32     bpak-transport       Encode: 9f7aacf9, Decode: b5964388
    =   2d44bbfb   32     bpak-transport       Encode: 57004cd0, Decode: b5bcc58f
    =   7c9b2f93   32     merkle-salt          7691130fef9adf5704e702261b151833a176f66c667cad0dc1fb436d7e52707c
    *   e68fc9be   32     merkle-root-hash     7a13e732655cb358779a21ca5fef5b2d6e1052ac791668679f5924f66362a1a1
    =   7da19399   4      bpak-key-id          a90f9680
    =   106c13a7   4      bpak-key-store       365f2120
    *   e5679b94   72     bpak-signature

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
    *   faabeca7   4194304      0      h-------       4194304
    *   77fadb17   36864        0      h-------       36864

.. toctree::
   :maxdepth: 1
   :glob:

   ug/*
