#!/bin/sh
BPAK=../src/bpak
V=-vvv
echo Creating keystore archive
set -e

$BPAK --help

IMG=test_keystore.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28
PKG_UNIQUE_ID_A=$(uuidgen)
set -e

# Create A package
echo Creating package A
$BPAK create $IMG -Y

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid -v
$BPAK add $IMG --meta keystore-provider-id --from-string test --encoder id

echo Adding first key
$BPAK add $IMG --part pb-development \
               --from-file $srcdir/secp256r1-pub-key.pem \
               --encoder key
echo Adding second key
$BPAK add $IMG --part pb-development2 \
               --from-file $srcdir/secp384r1-pub-key.pem \
               --encoder key

$BPAK add $IMG --part pb-development3 \
               --from-file $srcdir/secp521r1-pub-key.pem \
               --encoder key

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V
$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V

$BPAK show $IMG

$BPAK generate keystore $IMG --name test > test_keystore.c
cc -c test_keystore.c -I $srcdir/../include
