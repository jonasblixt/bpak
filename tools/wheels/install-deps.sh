#!/bin/sh
# Install the build dependencies of the python wheels in the manylinux and
# musllinux images of cibuildwheel, see [tool.cibuildwheel] in
# pyproject.toml.
#
# mbedtls is built from source and linked statically into the extension, so
# that the wheels use a supported mbedtls version. auditwheel copies liblzma
# into the wheels.

set -eu

MBEDTLS_VERSION=3.6.7
MBEDTLS_SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6

if command -v dnf > /dev/null; then
    dnf install -y bzip2 xz-devel
elif command -v yum > /dev/null; then
    yum install -y bzip2 xz-devel
else
    apk add bzip2 xz-dev
fi

work_dir=$(mktemp -d)
cd "$work_dir"

curl -fsSL -o mbedtls.tar.bz2 \
    "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VERSION/mbedtls-$MBEDTLS_VERSION.tar.bz2"
echo "$MBEDTLS_SHA256  mbedtls.tar.bz2" | sha256sum -c -
tar -xjf mbedtls.tar.bz2

# The release archive contains the generated files, GEN_FILES would need
# python modules that the images do not have
cmake -S "mbedtls-$MBEDTLS_VERSION" -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
    -DENABLE_PROGRAMS=OFF \
    -DENABLE_TESTING=OFF \
    -DGEN_FILES=OFF
cmake --build build -j "$(nproc)"
cmake --install build

cd /
rm -rf "$work_dir"
