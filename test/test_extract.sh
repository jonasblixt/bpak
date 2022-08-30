#!/bin/sh
BPAK=../src/bpak
set -ex
V=-vvv

IMG=extract_test.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd


dd if=/dev/urandom of=test_extract.data bs=1024 count=4096

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta test-meta --from-string "Test string"
$BPAK add $IMG --meta test-meta2 --from-string 0x11223344 --encoder integer

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK add $IMG --part fs \
               --from-file test_extract.data \
               --set-flag dont-hash \
               --encoder merkle $V

$BPAK extract $IMG --part fs --output test_extract.dump

first_sha256=$(sha256sum test_extract.dump | cut -d ' ' -f 1)
second_sha256=$(sha256sum test_extract.data | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK extract $IMG --meta test-meta --output test_extract.dump


if [ "$(cat test_extract.dump)" != "Test string" ];
then
    echo "Meta data mismatch"
    exit 1
fi

$BPAK extract $IMG --meta test-meta2 --output test_extract.dump
hexdump_string=$(hexdump -v -e '/1 "%02X "' < test_extract.dump)

if [ "$hexdump_string" != "44 33 22 11 00 00 00 00 " ];
then
    echo "Meta data mismatch ($hexdump_string)"
    exit 1
fi
