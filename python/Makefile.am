if BUILD_BPAK_PYTHON_LIB

pyexec_LTLIBRARIES = bpak.la

bpak_la_SOURCES = package.c

bpak_la_LDFLAGS = -avoid-version -module
bpak_la_CFLAGS = -I$(PYTHON_INCLUDES) \
                 -I$(top_srcdir)/include \
                 -I$(top_srcdir)/src \
                 -I$(top_srcdir)/src/mbedtls/include \
                 $(CODE_COVERAGE_CFLAGS)

bpak_la_LIBADD = $(top_builddir)/lib/libbpak.la
bpak_la_LIBS = $(CODE_COVERAGE_LIBS)
endif
