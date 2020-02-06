#!/bin/sh
BPAK=../src/bpak
set -e

$BPAK --help

IMG=test_dep_version.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen -t)
V=-vvv

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V
$BPAK add $IMG --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string 1.2.3 --encoder version $V
echo Adding first dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string f862352d-2444-41c2-96d8-538de6442162==0.1.0 \
               --encoder dependency $V
echo Adding second dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string 3d7eda1e-a4b3-431b-abf6-1cff2e21f9db\>=2.1.0 \
               --encoder dependency $V

echo Adding third dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string 3d7eda1e-a4b3-431b-abf6-1cff2e21f9db\>3.1.0 \
               --encoder dependency $V

$BPAK show $IMG $V
