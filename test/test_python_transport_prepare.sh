#!/bin/sh
BPAK=../src/bpak
TEST_SRC_DIR=$1
IMG_A=test_python_transport_A.bpak
PKG_UUID_A=0888b0fa-9c48-4524-9845-06a641b61edd
IMG_B=test_python_transport_B.bpak
PKG_UUID_B=0888b0fa-9c48-4524-9845-06a641b61edd
V=-vvvv
set -e

# Create A package
echo --- Creating package A ---
$BPAK create $IMG_A -Y $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID_A --encoder uuid $V

$BPAK transport $IMG_A --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_A --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_A --part fs \
                 --from-file $TEST_SRC_DIR/diff2_origin.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG_A --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG_A --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

# Create B package
echo --- Creating package B ---
$BPAK create $IMG_B -Y $V

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID_B --encoder uuid $V

$BPAK transport $IMG_B --add --part fs --encoder bsdiff \
                                       --decoder bspatch $V


$BPAK transport $IMG_B --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate $V

$BPAK add $IMG_B --part fs \
                 --from-file $TEST_SRC_DIR/diff2_target.bin \
                 --set-flag dont-hash \
                 --encoder merkle $V

$BPAK set $IMG_B --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG_B --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

