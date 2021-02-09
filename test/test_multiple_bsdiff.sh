#!/bin/sh
BPAK=../src/bpak
echo --- Creating simple archive ---
set -e

$BPAK --help

IMG_A=vA_transp.bpak
IMG_B=vB_transp.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen)
PKG_UNIQUE_ID_B=$(uuidgen)
V=-vvvv
set -e

dd if=/dev/urandom of=A_transp bs=1024 count=512
dd if=/dev/urandom of=A_transp2 bs=1024 count=512
dd if=/dev/urandom of=B__transp bs=1024 count=512
dd if=/dev/urandom of=B__transp2 bs=1024 count=512

cat A_transp B__transp > B_transp
cat A_transp2 B__transp2 > B_transp2

# Create A package
echo --- Creating package A ---
$BPAK create $IMG_A -Y $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG_A --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK transport $IMG_A --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_A --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK transport $IMG_A --add --part fs2 --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_A --add --part fs2-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_A --part fs \
                 --from-file A_transp \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_A --part fs2 \
                 --from-file A_transp2 \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem $V

# Create B package
echo --- Creating package B ---
$BPAK create $IMG_B -Y $V

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG_B --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_B \
                 --encoder uuid $V

$BPAK transport $IMG_B --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_B --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK transport $IMG_B --add --part fs2 --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_B --add --part fs2-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_B --part fs \
                 --from-file B_transp \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_B --part fs2 \
                 --from-file B_transp2 \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG_B --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_B --key $srcdir/secp256r1-key-pair.pem $V

# Test Transport encoding / decoding
echo --- Transport encoding ---

$BPAK transport $IMG_B --encode --origin $IMG_A \
                                --output vB_transport_bsdiff.bpak \
                                $V


echo --- Transport decoding ---

$BPAK transport vB_transport_bsdiff.bpak --decode \
                                  --origin $IMG_A \
                                  --output vB_install.bpak \
                                  $V

$BPAK compare $IMG_B vB_install.bpak $V

#sha256sum $IMG_B
#sha256sum vB_install.bpak
first_sha256=$(sha256sum $IMG_B | cut -d ' ' -f 1)
second_sha256=$(sha256sum vB_install.bpak | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show vB_transport_bsdiff.bpak $V
$BPAK show $IMG_B $V
