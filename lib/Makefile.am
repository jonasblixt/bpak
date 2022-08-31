lib_LTLIBRARIES = libbpak.la


libbpak_la_SOURCES = bpak.c \
                     bpakcrc.c \
                     keystore.c \
                     merkle.c \
                     utils.c \
                     id.c \
                     sais.c \
                     pkg.c \
                     pkg_create.c \
                     pkg_sign.c \
                     pkg_verify.c \
                     transport_decode.c \
                     transport_encode.c

libbpak_la_CFLAGS = -I$(top_srcdir)/include \
                     $(CODE_COVERAGE_CFLAGS)

libbpak_la_LDFLAGS =  -lmbedtls -lmbedcrypto

if BUILD_BPAK_CODECS

libbpak_la_SOURCES += heatshrink/heatshrink_decoder.c \
                      heatshrink/heatshrink_encoder.c \
                      bspatch.c \
                      bspatch_hs.c \
                      bsdiff.c \
                      bsdiff_hs.c

libbpak_la_CFLAGS += -DBUILD_BPAK_CODECS=1

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
                  $(top_srcdir)/include/bpak/transport.h \
                  $(top_srcdir)/include/bpak/bsdiff.h \
                  $(top_srcdir)/include/bpak/bsdiff_hs.h \
                  $(top_srcdir)/include/bpak/bspatch.h \
                  $(top_srcdir)/include/bpak/bspatch_hs.h \
                  $(top_srcdir)/include/bpak/heatshrink_decoder.h \
                  $(top_srcdir)/include/bpak/heatshrink_encoder.h
