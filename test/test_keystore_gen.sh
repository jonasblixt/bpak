#!/bin/bash
# Test: test_keystore_gen
#
# Description: creates a bpak archive with a few public keys and then
#               calls the c code generator
#
# Purpose: Test that the c code generator produces meningful output
#
BPAK=../src/bpak
TEST_NAME=test_keysytore_gen
TEST_SRC_DIR=$1/test
V=-vvv
set -e

IMG=${TEST_NAME}.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28

echo Creating package A
$BPAK create $IMG -Y

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG --meta keystore-provider-id --from-string test --encoder id

echo Adding first key
$BPAK add $IMG --part pb-development \
               --from-file $TEST_SRC_DIR/secp256r1-pub-key.pem \
               --encoder key
echo Adding second key
$BPAK add $IMG --part pb-development2 \
               --from-file $TEST_SRC_DIR/secp384r1-pub-key.pem \
               --encoder key

$BPAK add $IMG --part pb-development3 \
               --from-file $TEST_SRC_DIR/secp521r1-pub-key.pem \
               --encoder key

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V
$BPAK sign $IMG --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

$BPAK show $IMG

$BPAK generate keystore $IMG --name test > test_keystore.c
cc -c test_keystore.c -I $TEST_SRC_DIR/../include -I../lib
