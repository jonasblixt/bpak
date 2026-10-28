#!/usr/bin/env python3

from pathlib import Path
from setuptools import setup
from setuptools import Extension

def read_version():
    version_file = Path(__file__).resolve().parent.parent / "version.txt"
    return version_file.read_text().strip()

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
