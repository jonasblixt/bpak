lib_LTLIBRARIES = libbpak.la


libbpak_la_SOURCES = bpak.c \
                     bpakcrc.c \
                     io.c \
                     file.c \
					 fifo.c \
                     keystore.c \
                     merkle.c \
                     sha256.c \
                     sha512.c \
                     alg.c \
                     utils.c \
                     sais.c \
                     pkg.c \
					 uuid/unparse.c \
					 uuid/unpack.c

libbpak_la_CFLAGS = -I$(top_srcdir)/include \
                     $(CODE_COVERAGE_CFLAGS)

if BUILD_BPAK_CODECS

libbpak_la_SOURCES += heatshrink/heatshrink_decoder.c \
                      heatshrink/heatshrink_encoder.c \
                      alg_heatshrink.c \
                      alg_remove.c \
                      alg_merkle.c \
                      alg_bspatch.c \
                      alg_bsdiff.c

libbpak_la_CFLAGS += -DBUILD_BPAK_CODECS=1

endif



pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = bpak.pc

libbpak_la_LIBS = $(CODE_COVERAGE_LIBS)

pkginclude_HEADERS = $(top_srcdir)/include/bpak/bpak.h \
                  $(top_srcdir)/include/bpak/crc.h \
                  $(top_srcdir)/include/bpak/io.h \
                  $(top_srcdir)/include/bpak/file.h \
                  $(top_srcdir)/include/bpak/fifo.h \
                  $(top_srcdir)/include/bpak/keystore.h \
                  $(top_srcdir)/include/bpak/merkle.h \
                  $(top_srcdir)/include/bpak/utils.h \
                  $(top_srcdir)/include/bpak/alg.h \
                  $(top_srcdir)/include/bpak/pkg.h
