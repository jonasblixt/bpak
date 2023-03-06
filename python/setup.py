#!/usr/bin/env python3

from setuptools import setup
from setuptools import Extension
import re

def read_version():
    with open("../include/bpak/version.h", "r") as f:
        return re.search(r"BPAK_VERSION_STRING \"(.*)\"$",
                         f.read(),
                         re.MULTILINE).group(1)

setup(name='bpak',
      version=read_version(),
      description="BPAK python wrapper",
      author="Jonas Blixt",
      author_email="jonpe960@gmail.com",
      license="BSD",
      url="https://github.com/jonasblixt/bpak",
      ext_modules=[
          Extension(name="bpak",
                        sources=[
                            "meta.c",
                            "part.c",
                            "package.c",
                            "python_wrapper.c"
                        ],
                    libraries=["bpak"],
                    )
      ],
)
