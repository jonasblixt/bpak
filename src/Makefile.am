if BPAK_BUILD_CLI

bin_PROGRAMS = bpak

bpak_SOURCES  = main.c \
                misc.c \
                show.c \
                sign.c \
                generate.c \
                transport.c \
                compare.c \
                extract.c

bpak_CFLAGS  = -I$(top_srcdir)/include \
			   $(LIBUUID_CFLAGS) \
               $(CODE_COVERAGE_CFLAGS) \
			   -Wall -Werror

if BPAK_BUILD_MERKLE
bpak_CFLAGS  += -DBPAK_BUILD_MERKLE
endif

if BPAK_BUILD_PKG_CREATE
bpak_SOURCES += create.c add.c set.c
bpak_CFLAGS  += -DBPAK_BUILD_PKG_CREATE
endif

if BPAK_BUILD_TRANSPORT_ENCODE
bpak_CFLAGS  += -DBPAK_BUILD_TRANSPORT_ENCODE
endif

if BPAK_BUILD_PKG_SIGN
bpak_CFLAGS  += -DBPAK_BUILD_PKG_SIGN
endif

bpak_LDFLAGS = $(LIBUUID_LIBS) -lmbedtls -lmbedcrypto

bpak_LIBS = $(CODE_COVERAGE_LIBS)

bpak_LDADD = $(top_builddir)/lib/libbpak.la

endif
