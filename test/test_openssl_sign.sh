#!/bin/sh
BPAK=../src/bpak
echo Sign openssl resign
set -e
V=-vvv

IMG=openssl_sign_test2.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

# Create A package
echo Creating package A
rm -f $IMG
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

dd if=/dev/urandom of=A_transp bs=1024 count=4096

$BPAK add $IMG --part fs \
               --from-file A_transp \
               --set-flag dont-hash \
               --encoder merkle $V

dd if=/dev/urandom of=B bs=1024 count=4096

$BPAK add $IMG --part B_img \
               --from-file B $V

$BPAK show $IMG

$BPAK show $IMG --binary-hash | openssl pkeyutl -sign -inkey $srcdir/secp256r1-key-pair.pem \
                    -keyform PEM > /tmp/sig.data

$BPAK sign $IMG --signature /tmp/sig.data

$BPAK show $IMG $V

$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V

