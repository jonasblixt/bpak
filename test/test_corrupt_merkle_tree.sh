# Test: test_corrupt_merkle_tree
#
# Description: This test creates an archive with a data block that has a 
#  merkle hash tree, signs the archive and then introduces a corruption in the
#  merkle tree part.
#
# Purpose: To ensure that the verify function correctly rebuilds the hash
#  tree from the data and detects the corrupt portion.
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_corrupt_merkle_tree
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

create_data ${TEST_NAME}_data.bin 128

echo $TEST_NAME Creating package
$BPAK create $IMG -Y $V
$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --part fs \
                 --from-file ${TEST_NAME}_data.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG --key-id pb-development \
                 --keystore-id pb-internal $V
echo SIGN
$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V
echo VERIFY
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V

# Introduce corruption in the merkle tree part, the merkle is located 
#  at an offset of 4KiB (header) + 128KiB data, write some zeros in the begining.
dd if=/dev/zero of=$IMG bs=1 seek=135168 count=16 conv=notrunc
set +e
echo VERIFY
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V
result_code=$?
if [ $result_code -ne 236 ];
then
    exit $result_code
fi

echo $TEST_NAME End
