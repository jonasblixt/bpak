#!/bin/bash
# Test: test_set_string
#
# Description: Creates meta data fields and updates them using the set command
#
# Purpose: To test the set command with different encoders
#
#
BPAK=../src/bpak
TEST_NAME=test_set_string
TEST_SRC_DIR=$1/test
set -e
V=-vvvv

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
TEST_STRING="Hello World"

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V
$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG --meta some-meta-tag --from-string "Hello" $V
$BPAK set $IMG --meta some-meta-tag --from-string "$TEST_STRING" $V
$BPAK show $IMG $V
result_str=$($BPAK extract $IMG --meta some-meta-tag)

if [ "$result_str" != "$TEST_STRING" ];
then
    echo "String comparison failed $result_str != $TEST_STRING"
    exit 1
fi

# Create a meta data using the id encoder
$BPAK add $IMG --meta meta-id --from-string "Hello" --encoder id $V
id_data_sha=$($BPAK extract $IMG --meta meta-id | sha256sum)

if [ "$id_data_sha" != "5d562b6bf4a550dc64bf260348264d2d77045d7517a322858b0195af0dd2aef8  -" ];
then
    echo "ID data comparison failed"
    exit 1
fi

# Update the meta data using the id encoder
$BPAK set $IMG --meta meta-id --from-string "World" --encoder id $V
id_data_sha=$($BPAK extract $IMG --meta meta-id | sha256sum)

if [ "$id_data_sha" != "8e46045788da5734a44a9eb42b632f1453e16286b57390bb9f930a60177bbce7  -" ];
then
    echo "ID data comparison failed"
    exit 1
fi

# Create a meta data using the integer encoder
$BPAK add $IMG --meta meta-id2 --from-string 0x11223344 --encoder integer $V
id_data_sha=$($BPAK extract $IMG --meta meta-id2 | sha256sum)

if [ "$id_data_sha" != "8b7ddf2ac626146bf9b95719501bd207935bcb20a095ab6d19c9800b019715de  -" ];
then
    echo "Int data comparison failed"
    exit 1
fi

# Update the meta data using the integer encoder
$BPAK set $IMG --meta meta-id2 --from-string 0x55667788 --encoder integer $V
id_data_sha=$($BPAK extract $IMG --meta meta-id2 | sha256sum)

if [ "$id_data_sha" != "1743d272a5e68230be47ed8052c2bbe14f3b6d0628a21c9e894c5919c21ca633  -" ];
then
    echo "Int data comparison failed"
    exit 1
fi
