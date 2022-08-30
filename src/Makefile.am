if BUILD_BPAK_TOOL

bin_PROGRAMS = bpak

bpak_SOURCES  = main.c \
                misc.c \
                show.c \
                create.c \
                add.c \
                sign.c \
                generate.c \
                transport.c \
                compare.c \
                set.c \
                extract.c

bpak_CFLAGS  = -I$(top_srcdir)/include \
			   $(LIBUUID_CFLAGS) \
               $(CODE_COVERAGE_CFLAGS)

bpak_LDFLAGS = $(LIBUUID_LIBS) -lmbedtls -lmbedcrypto

bpak_LIBS = $(CODE_COVERAGE_LIBS)

bpak_LDADD = $(top_builddir)/lib/libbpak.la

endif
