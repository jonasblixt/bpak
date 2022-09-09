# Test: test_signec384
#
# Description: This test creates an archive and signs/verifies it with an
#  ec384 key
#
# Purpose: To test the sign/verify commands with an ec384 key
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_signec384
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

$BPAK create $IMG -Y --hash-kind sha384 --signature-kind secp384r1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid -v

$BPAK set $IMG --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG --key $TEST_SRC_DIR/secp384r1-key-pair.pem $V

$BPAK show $IMG $V
$BPAK verify $IMG --key $TEST_SRC_DIR/secp384r1-pub-key.der $V

