"""BPAK setuptools configuration."""

import re
from pathlib import Path

from setuptools import Extension, setup


def read_version():
    text = Path("include/bpak/version.h").read_text()
    return re.search(r'BPAK_VERSION_STRING "(.+)"', text).group(1)


# NOTE: Keep in sync with lib/CMakeLists.txt (authoritative source list)
_lib_sources = [
    "lib/bpak.c",
    "lib/bpakcrc.c",
    "lib/id.c",
    "lib/keystore.c",
    "lib/mem.c",
    "lib/utils.c",
    "lib/bsdiff.c",
    "lib/bspatch.c",
    "lib/merkle.c",
    "lib/pkg.c",
    "lib/pkg_create.c",
    "lib/pkg_sign.c",
    "lib/pkg_verify.c",
    "lib/sais.c",
    "lib/transport_decode.c",
    "lib/transport_encode.c",
    "lib/verify.c",
    "lib/heatshrink/heatshrink_decoder.c",
    "lib/heatshrink/heatshrink_encoder.c",
    "lib/crypto.c",
    "lib/mbedtls_wrapper.c",
    "lib/keystore_load_from_file.c",
    "ext/uuid/unpack.c",
    "ext/uuid/unparse.c",
]

_wrapper_sources = [
    "python/python_wrapper.c",
    "python/package.c",
    "python/meta.c",
    "python/part.c",
]

setup(
    name="bpak",
    version=read_version(),
    description="BPAK - Bit Packer",
    long_description=Path("README.rst").read_text(),
    long_description_content_type="text/x-rst",
    author="Jonas Blixt",
    author_email="jonpe960@gmail.com",
    license="BSD",
    url="https://github.com/jonasblixt/bpak",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Embedded Systems",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
    ],
    packages=["bpak"],
    package_dir={"bpak": "python/bpak"},
    ext_modules=[
        Extension(
            name="bpak._bpak",
            sources=_wrapper_sources + _lib_sources,
            include_dirs=["include", "ext/uuid", "python"],
            define_macros=[("BPAK_HAVE_USER_SETTINGS", "1")],
            libraries=["mbedcrypto", "lzma"],
            extra_compile_args=["-fvisibility=hidden"],
        )
    ],
    install_requires=["click>=8.0"],
    entry_points={
        "console_scripts": ["bpak=bpak.__main__:cli"],
    },
)
