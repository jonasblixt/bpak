if BPAK_BUILD_TOOL

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

if BPAK_BUILD_PKG_CREATE
bpak_SOURCES += create.c add.c set.c
endif

bpak_LDFLAGS = $(LIBUUID_LIBS) -lmbedtls -lmbedcrypto

bpak_LIBS = $(CODE_COVERAGE_LIBS)

bpak_LDADD = $(top_builddir)/lib/libbpak.la

endif
