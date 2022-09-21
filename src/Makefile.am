if BPAK_BUILD_TOOL

bin_PROGRAMS = bpak

bpak_SOURCES  = main.c \
                misc.c \
                show.c \
                sign.c \
                generate.c \
                transport.c \
                compare.c \
                extract.c \
                uuid/clear.c \
                uuid/compare.c \
                uuid/copy.c \
                uuid/isnull.c \
                uuid/pack.c \
                uuid/parse.c \
                uuid/unpack.c \
                uuid/unparse.c

bpak_CFLAGS  = -I$(top_srcdir)/include \
               $(CODE_COVERAGE_CFLAGS) \
               -Wall -Werror

if BPAK_BUILD_PKG_CREATE
bpak_SOURCES += create.c add.c set.c
endif

bpak_LDFLAGS = -lmbedtls -lmbedcrypto

bpak_LIBS = $(CODE_COVERAGE_LIBS)

bpak_LDADD = $(top_builddir)/lib/libbpak.la

endif
