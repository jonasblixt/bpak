#!/bin/sh
BPAK=../src/bpak
IMG=test_python_lib.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID=$(uuidgen)
V=-vvvv
set -e

dd if=/dev/urandom of=A_transp bs=1024 count=4096

# Create A package
echo --- Creating package A ---
$BPAK create $IMG -Y $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK transport $IMG --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG --part fs \
                 --from-file A_transp \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V

