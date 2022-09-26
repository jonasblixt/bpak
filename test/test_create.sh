#!/bin/bash
# Test: test_create
#
# Description: This test creates an archive with a data block that has a 
#  merkle hash tree, signs the archive and then verifies it
#
# Purpose: To test some of the basic functionallity when creating new archives
#  and the sign/verfy steps
#

BPAK=../src/bpak
TEST_NAME=test_create
TEST_SRC_DIR=$1/test
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
$BPAK sign $IMG --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V
echo SHOW
$BPAK show $IMG $V
echo VERIFY
$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V
echo SHOW
$BPAK show $IMG --part fs $V
$BPAK show $IMG --meta bpak-package $V

echo $TEST_NAME End
