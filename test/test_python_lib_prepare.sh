#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_python_lib
TEST_SRC_DIR=$1
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

$BPAK create $IMG -Y $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK transport $IMG --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG --part fs \
                 --from-file $TEST_SRC_DIR/diff2_origin.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

