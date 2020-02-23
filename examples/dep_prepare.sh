#!/bin/sh
BPAK=bpak
set -e
V=-vvv

# Create top package

IMG=top.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "1.0.0" $V

$BPAK add $IMG --meta bpak-dependency \
               --from-string "6a934c57-2976-4d64-be3f-ebd7ed20d40c:>=0.1.0 <2.0.0" \
               $V

# Create a-1.0.0 package

IMG=a-1.0.0.bpak
PKG_UUID=6a934c57-2976-4d64-be3f-ebd7ed20d40c

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "1.0.0" $V

$BPAK add $IMG --meta bpak-dependency \
               --from-string "ca438c33-d6fb-4e31-90c8-8c52c09dfdf5:>=0.1.0 <1.0.0" \
               $V



# Create a-1.2.0 package

IMG=a-1.2.0.bpak
PKG_UUID=6a934c57-2976-4d64-be3f-ebd7ed20d40c

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "1.2.0" $V

$BPAK add $IMG --meta bpak-dependency \
               --from-string "ca438c33-d6fb-4e31-90c8-8c52c09dfdf5:>=0.1.0 <1.0.0" \
               $V

# Create a-2.0.0 package

IMG=a-2.0.0.bpak
PKG_UUID=6a934c57-2976-4d64-be3f-ebd7ed20d40c

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "2.0.0" $V

$BPAK add $IMG --meta bpak-dependency \
               --from-string "ca438c33-d6fb-4e31-90c8-8c52c09dfdf5:>=0.1.0 <1.0.0" \
               $V


# Create b-0.2.0 package (variant 1)

IMG=b-0.2.0-1.bpak
PKG_UUID=ca438c33-d6fb-4e31-90c8-8c52c09dfdf5

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "0.2.0" $V

$BPAK add $IMG --meta variant --from-string "var1" $V

# Create b-0.2.0 package (variant 2)

IMG=b-0.2.0-2.bpak
PKG_UUID=ca438c33-d6fb-4e31-90c8-8c52c09dfdf5

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "0.2.0" $V

$BPAK add $IMG --meta variant --from-string "var2" $V


