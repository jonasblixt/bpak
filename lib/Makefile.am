lib_LTLIBRARIES = libbpak.la


libbpak_la_SOURCES = bpak.c \
                     bpakcrc.c \
                     keystore.c \
                     utils.c \
                     id.c \
                     pkg.c \
                     pkg_verify.c \
                     verify.c \
					 mem.c \
                     transport_decode.c

libbpak_la_CFLAGS = -I$(top_srcdir)/include \
                     $(CODE_COVERAGE_CFLAGS) \
					 -Wall -Werror -DBPAK_BUILD_MBEDTLS

libbpak_la_LDFLAGS =  -lmbedtls -lmbedcrypto

if BPAK_BUILD_MERKLE
libbpak_la_SOURCES += merkle.c
endif

if BPAK_BUILD_BSDIFF
libbpak_la_SOURCES += bsdiff.c sais.c heatshrink/heatshrink_encoder.c
endif

if BPAK_BUILD_BSPATCH
libbpak_la_SOURCES += bspatch.c heatshrink/heatshrink_decoder.c
endif

if BPAK_BUILD_PKG_CREATE
libbpak_la_SOURCES += pkg_create.c
endif

if BPAK_BUILD_TRANSPORT_ENCODE
libbpak_la_SOURCES += transport_encode.c
endif

if BPAK_BUILD_PKG_SIGN
libbpak_la_SOURCES += pkg_sign.c
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = bpak.pc

libbpak_la_LIBS = $(CODE_COVERAGE_LIBS)

pkginclude_HEADERS = $(top_srcdir)/include/bpak/bpak.h \
                  $(top_srcdir)/include/bpak/crc.h \
                  $(top_srcdir)/include/bpak/keystore.h \
                  $(top_srcdir)/include/bpak/merkle.h \
                  $(top_srcdir)/include/bpak/utils.h \
                  $(top_srcdir)/include/bpak/id.h \
                  $(top_srcdir)/include/bpak/pkg.h \
                  $(top_srcdir)/include/bpak/verify.h \
                  $(top_srcdir)/include/bpak/transport.h \
                  $(top_srcdir)/include/bpak/bsdiff.h \
                  $(top_srcdir)/include/bpak/bspatch.h
