lib_LTLIBRARIES = libbpak.la


libbpak_la_SOURCES = bpak.c \
                     bpakcrc.c \
                     keystore.c \
                     utils.c \
                     id.c \
                     pkg.c \
                     pkg_verify.c \
                     verify.c \
                     transport_decode.c

libbpak_la_CFLAGS = -I$(top_srcdir)/include \
                     $(CODE_COVERAGE_CFLAGS)

libbpak_la_LDFLAGS =  -lmbedtls -lmbedcrypto

if BPAK_BUILD_MERKLE
libbpak_la_SOURCES += merkle.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_MERKLE
endif

if BPAK_BUILD_BSDIFF
libbpak_la_SOURCES += bsdiff.c bsdiff_hs.c sais.c heatshrink/heatshrink_encoder.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_BSDIFF
endif

if BPAK_BUILD_BSPATCH
libbpak_la_SOURCES += bspatch.c bspatch_hs.c heatshrink/heatshrink_decoder.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_BSPATCH
endif

if BPAK_BUILD_PKG_CREATE
libbpak_la_SOURCES += pkg_create.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_PKG_CREATE
endif

if BPAK_BUILD_TRANSPORT_ENCODE
libbpak_la_SOURCES += transport_encode.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_TRANSPORT_ENCODE
endif

if BPAK_BUILD_PKG_SIGN
libbpak_la_SOURCES += pkg_sign.c
libbpak_la_CFLAGS  += -DBPAK_BUILD_PKG_SIGN
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
                  $(top_srcdir)/include/bpak/bsdiff_hs.h \
                  $(top_srcdir)/include/bpak/bspatch.h \
                  $(top_srcdir)/include/bpak/bspatch_hs.h \
                  $(top_srcdir)/include/bpak/heatshrink_decoder.h \
                  $(top_srcdir)/include/bpak/heatshrink_encoder.h
