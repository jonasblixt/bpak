Dependencies
============

Bit packer does not directly support dependency management but it does however
include some support structures for it. There is a special meta data encoder
called 'dependency' which can encode a UUID and semver tuple.

Suppose we want to express and add a dependency to this package::

    $ bpak show package.bpak

    BPAK File: package.bpak

    Hash:        sha256
    Signature:   prime256v1
    Key ID:      a90f9680
    Keystore ID: 365f2120

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    0888b0fa-9c48-4524-9845-06a641b61edd
        79c3b7b4   16
        2d44bbfb   32     bpak-transport       faabeca7   Encode: 9f7aacf9, Decode: b5964388
        2d44bbfb   32     bpak-transport       77fadb17   Encode: 57004cd0, Decode: b5bcc58f
        7c9b2f93   32     merkle-salt          faabeca7   8b018b5fc110854675aeef18248a41219badf06fa2c77e579773673b367ef06b
        e68fc9be   32     merkle-root-hash     faabeca7   f780bf7199e28ea6b1d03b17211c95b26400bb9fb46b26f41a6658e3e00efb1b

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   1048576      0      h-------       1048576
        77fadb17   12288        0      h-------       12288

    Hash: f388d1caeaae78414e6889b4e23d366dda099c4572d911e9cde487ff9ff10dba

Adding a dependency::

    $ bpak add package.bpak --meta bpak-dependency --from-string="f862352d-2444-41c2-96d8-538de6442162:>=0.1.0 <1.0.0" --encoder dependency

This means that we depend on a package with uuid f862352d-2444-41c2-96d8-538de6442162
where the version must be greater or equal to 0.1.0 and less then 1.0.0.

Package after adding dependency::

    $ bpak show package.bpak

    BPAK File: package.bpak

    Hash:        sha256
    Signature:   prime256v1
    Key ID:      a90f9680
    Keystore ID: 365f2120

    Metadata:
        ID         Size   Meta ID              Part Ref   Data
        fb2f1f3f   16     bpak-package                    0888b0fa-9c48-4524-9845-06a641b61edd
        79c3b7b4   16
        2d44bbfb   32     bpak-transport       faabeca7   Encode: 9f7aacf9, Decode: b5964388
        2d44bbfb   32     bpak-transport       77fadb17   Encode: 57004cd0, Decode: b5bcc58f
        7c9b2f93   32     merkle-salt          faabeca7   8b018b5fc110854675aeef18248a41219badf06fa2c77e579773673b367ef06b
        e68fc9be   32     merkle-root-hash     faabeca7   f780bf7199e28ea6b1d03b17211c95b26400bb9fb46b26f41a6658e3e00efb1b
        0ba87349   30     bpak-dependency                 f862352d-2444-41c2-96d8-538de6442162 (>=0.1.0 <1.0.0)

    Parts:
        ID         Size         Z-pad  Flags          Transport Size
        faabeca7   1048576      0      h-------       1048576
        77fadb17   12288        0      h-------       12288

    Hash: 042ccac9746f759c25e6dcc0f4fb12752208f27742616fbfc00cb14fc88733fb

Note the added 'bpak-dependency' meta data.


