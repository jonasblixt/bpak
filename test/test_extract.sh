#!/bin/bash
# Test: test_extract
#
# Description: This test creates an archive with data and meta data and
#  then tests the 'extract' command
#
# Purpose: To ensure that the extract command can extract part data and meta
#  data from an archive
#

BPAK=../src/bpak
TEST_NAME=test_extract
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

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta test-meta --from-string "Test string"
$BPAK add $IMG --meta test-meta2 --from-string 0x11223344 --encoder integer

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK add $IMG --part fs \
               --from-file ${TEST_NAME}_data.bin \
               --set-flag dont-hash \
               --encoder merkle $V

$BPAK extract $IMG --part fs --output ${TEST_NAME}_dump.bin

first_sha256=$(sha256sum ${TEST_NAME}_dump.bin | cut -d ' ' -f 1)
second_sha256=$(sha256sum ${TEST_NAME}_data.bin | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK extract $IMG --meta test-meta --output ${TEST_NAME}_meta_dump.bin

if [ "$(cat ${TEST_NAME}_meta_dump.bin)" != "Test string" ];
then
    echo "Meta data mismatch"
    exit 1
fi

$BPAK extract $IMG --meta test-meta2 --output ${TEST_NAME}_meta_dump2.bin
hexdump_string=$(hexdump -v -e '/1 "%02X "' < ${TEST_NAME}_meta_dump2.bin)

if [ "$hexdump_string" != "44 33 22 11 00 00 00 00 " ];
then
    echo "Meta data mismatch ($hexdump_string)"
    exit 1
fi
