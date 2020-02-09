#!/bin/sh
BPAK=../src/bpak
echo Creating simple archive
pwd
set -e

$BPAK --help

IMG_A=vA.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen -t)
set -e

dd if=/dev/urandom of=A bs=1024 count=4096

# Create A package
echo Creating package A
$BPAK create $IMG_A -Y

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG_A --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid -v

$BPAK transport $IMG_A --add --part fs --encoder bsdiff \
                                       --decoder bspatch -v


$BPAK transport $IMG_A --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate

$BPAK add $IMG_A --part fs \
                 --from-file A \
                 --set-flag dont-hash \
                 --encoder merkle -v

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem \
                  --key-id pb-development \
                  --key-store pb-internal -v

$BPAK show $IMG_A -vvv
$BPAK verify $IMG_A --key $srcdir/secp256r1-pub-key.der -vvv
$BPAK show $IMG_A --part fs -vvv
$BPAK show $IMG_A --meta bpak-package -vvv
