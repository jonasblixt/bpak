#!/bin/sh
BPAK=../src/bpak
echo --- Creating simple archive ---
set -e

$BPAK --help

IMG_A=vA_multi.bpak
IMG_B=vB_multi.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen)
PKG_UNIQUE_ID_B=$(uuidgen)
V=-vvvv
set -e

dd if=/dev/urandom of=p0A bs=1024 count=64
dd if=/dev/urandom of=p0A_ bs=1024 count=32
cat p0A p0A_ > p0B

dd if=/dev/urandom of=p1A bs=1024 count=64
dd if=/dev/urandom of=p1A_ bs=1024 count=32
cat p1A p1A_ > p1B

dd if=/dev/urandom of=p2A bs=1024 count=64
dd if=/dev/urandom of=p2A_ bs=1024 count=32
cat p2A p2A_ > p2B

dd if=/dev/urandom of=p3A bs=1024 count=64
dd if=/dev/urandom of=p3A_ bs=1024 count=32
cat p3A p3A_ > p3B

dd if=/dev/urandom of=p4A bs=1024 count=64
dd if=/dev/urandom of=p4A_ bs=1024 count=32
cat p4A p4A_ > p4B

dd if=/dev/urandom of=p5A bs=1024 count=64
dd if=/dev/urandom of=p5A_ bs=1024 count=32
cat p5A p5A_ > p5B

# Create A package
echo --- Creating package A ---
$BPAK create $IMG_A -Y $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG_A --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK transport $IMG_A --add --part p0 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_A --add --part p1 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_A --add --part p2 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_A --add --part p3 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_A --add --part p4 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_A --add --part p5 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK add $IMG_A --part p0 \
                 --from-file p0A $V

$BPAK add $IMG_A --part p1 \
                 --from-file p1A $V

$BPAK add $IMG_A --part p2 \
                 --from-file p2A $V

$BPAK add $IMG_A --part p3 \
                 --from-file p3A $V

$BPAK add $IMG_A --part p4 \
                 --from-file p4A $V

$BPAK add $IMG_A --part p5 \
                 --from-file p5A $V

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem $V

# Create B package
echo --- Creating package B ---
$BPAK create $IMG_B -Y $V

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG_B --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_B \
                 --encoder uuid $V

$BPAK transport $IMG_B --add --part p0 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_B --add --part p1 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_B --add --part p2 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_B --add --part p3 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_B --add --part p4 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_B --add --part p5 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK add $IMG_B --part p0 \
                 --from-file p0B $V

$BPAK add $IMG_B --part p1 \
                 --from-file p1B $V

$BPAK add $IMG_B --part p2 \
                 --from-file p2B $V

$BPAK add $IMG_B --part p3 \
                 --from-file p3B $V

$BPAK add $IMG_B --part p4 \
                 --from-file p4B $V

$BPAK add $IMG_B --part p5 \
                 --from-file p5B $V

$BPAK set $IMG_B --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_B --key $srcdir/secp256r1-key-pair.pem $V

# Test Transport encoding / decoding
echo --- Transport encoding ---

$BPAK transport $IMG_B --encode --origin $IMG_A \
                                --output vB_multi_transport.bpak \
                                $V


echo --- Transport decoding ---

$BPAK transport vB_multi_transport.bpak --decode \
                                  --origin $IMG_A \
                                  --output vB_multi_install.bpak \
                                  $V

$BPAK compare $IMG_B vB_multi_install.bpak $V

#sha256sum $IMG_B
#sha256sum vB_install.bpak
first_sha256=$(sha256sum $IMG_B | cut -d ' ' -f 1)
second_sha256=$(sha256sum vB_multi_install.bpak | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show vB_multi_transport.bpak $V
$BPAK show $IMG_B $V
