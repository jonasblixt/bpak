# build image from bpak root folder
FROM python:slim

RUN apt-get update -y && apt-get install -y \
    gcc \
    libmbedtls-dev \
    liblzma-dev

COPY . .

RUN pip install .
