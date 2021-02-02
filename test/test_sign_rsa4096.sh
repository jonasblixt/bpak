#!/bin/sh
BPAK=../src/bpak
echo Sign test rsa4096
set -e
V=-vvv

IMG=sign_test_rsa4096.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen)
set -e

# Create A package
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind rsa4096 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG --key $srcdir/dev_rsa_private.pem $V

$BPAK show $IMG $V
$BPAK verify $IMG --key $srcdir/dev_rsa_public.der $V
