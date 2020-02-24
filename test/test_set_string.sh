#!/bin/sh
BPAK=../src/bpak
echo Update string meta
set -e
V=-vvvv

IMG=set_test.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

# Create A package
echo Creating package A
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta some-meta-tag --from-string "Hello" $V

$BPAK show $IMG $V

$BPAK set $IMG --meta some-meta-tag --from-string "Hello World" $V

$BPAK show $IMG $V
