#!/bin/sh
BPAK=../src/bpak
V=-vvv
echo Sign test ec256
pwd
set -e

$BPAK --help

IMG_A=sign_test.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen -t)
set -e

# Create A package
echo Creating package A
$BPAK create $IMG_A -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG_A --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem $V

$BPAK show $IMG_A $V
$BPAK verify $IMG_A --key $srcdir/secp256r1-pub-key.der $V
