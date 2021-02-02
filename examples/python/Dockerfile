# build image from bpak root folder
from python:slim

RUN apt-get update -y

RUN apt-get install -y gcc
RUN apt-get install -y pkgconf
RUN apt-get install -y autoconf-archive
RUN apt-get install -y libtool
RUN apt-get install -y make

COPY . .

RUN autoreconf -fi
RUN ./configure --enable-python-library --disable-dependency-tracking
RUN make
RUN make install
RUN ldconfig
