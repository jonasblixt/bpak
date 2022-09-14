# Test: test_multiple_bsdiff
#
# Description: Create archives with two diff'able parts
#
# Purpose: Test that creation, transport encoding and decoding works
#   when an archive has more than one part that should be diffed/patched
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_multiple_bsdiff
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG_A=${TEST_NAME}_origin.bpak
IMG_B=${TEST_NAME}_target.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

# Create A package
echo --- Creating package A ---
$BPAK create $IMG_A -Y $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK transport $IMG_A --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_A --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK transport $IMG_A --add --part fs2 --encoder bsdiff \
                                       --decoder bspatch $V

$BPAK transport $IMG_A --add --part data --encoder bsdiff \
                                       --decoder bspatch $V

$BPAK transport $IMG_A --add --part fs2-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_A --part fs \
                 --from-file ${TEST_SRC_DIR}/diff2_origin.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_A --part fs2 \
                 --from-file ${TEST_SRC_DIR}/diff2_origin.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_A --part data \
                 --from-file ${TEST_SRC_DIR}/diff3_origin.bin $V

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_A --key ${TEST_SRC_DIR}/secp256r1-key-pair.pem $V

# Create B package
echo --- Creating package B ---
$BPAK create $IMG_B -Y $V

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK transport $IMG_B --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_B --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK transport $IMG_B --add --part fs2 --encoder bsdiff \
                                       --decoder bspatch $V

$BPAK transport $IMG_B --add --part data --encoder bsdiff \
                                       --decoder bspatch $V

$BPAK transport $IMG_B --add --part fs2-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_B --part fs \
                 --from-file ${TEST_SRC_DIR}/diff2_target.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_B --part fs2 \
                 --from-file ${TEST_SRC_DIR}/diff2_target.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK add $IMG_B --part data \
                 --from-file ${TEST_SRC_DIR}/diff3_target.bin $V

$BPAK set $IMG_B --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_B --key $srcdir/secp256r1-key-pair.pem $V

# Test Transport encoding / decoding
echo --- Transport encoding ---

$BPAK transport $IMG_B --encode --origin $IMG_A \
                                --output ${TEST_NAME}_patch.bpak \
                                $V


echo --- Transport decoding ---

$BPAK transport ${TEST_NAME}_patch.bpak --decode \
                                  --origin $IMG_A \
                                  --output ${TEST_NAME}_install.bpak \
                                  $V

$BPAK compare $IMG_B ${TEST_NAME}_install.bpak $V

#sha256sum $IMG_B
#sha256sum vB_install.bpak
first_sha256=$(sha256sum $IMG_B | cut -d ' ' -f 1)
second_sha256=$(sha256sum ${TEST_NAME}_install.bpak | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show ${TEST_NAME}_patch.bpak $V
$BPAK show $IMG_B $V
