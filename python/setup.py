#!/usr/bin/env python3

import re
from setuptools import setup
from setuptools import find_packages
from setuptools import Extension

setup(name='bpak',
      version="0.3.0",
      description='Bitpacker firmware',
      long_description=open('README.rst', 'r').read(),
      author='Jonas Blixt',
      author_email='jonpe960@gmail.com',
      license='BSD',
      classifiers=[
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3',
      ],
      url='https://github.com/jonasblixt/bpak',
      packages=find_packages(exclude=['tests']),
      install_requires=[
      ],
      ext_modules=[
          Extension(name="bpak",
                    libraries=["bpak"],
                    sources=[
                        "package.c",
                    ]),
      ],
      test_suite="tests")
