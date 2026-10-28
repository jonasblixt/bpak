# Build the image from the bpak root folder:
#   docker build -f examples/python/Dockerfile .
FROM python:3.13-slim

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends gcc libc6-dev libmbedtls-dev liblzma-dev

COPY . /bpak
RUN pip install /bpak
