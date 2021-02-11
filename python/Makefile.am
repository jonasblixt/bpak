if BUILD_BPAK_PYTHON_LIB

bpakdir = $(pkgpythondir)
bpak_PYTHON = bpak.py

pyexec_LTLIBRARIES = _bpak.la

_bpak_la_SOURCES = package.c

_bpak_la_LDFLAGS = -avoid-version -module
_bpak_la_CFLAGS = -I$(PYTHON_INCLUDES) \
                 -I$(top_srcdir)/include \
                 -I$(top_srcdir)/src \
                 -I$(top_srcdir)/src/mbedtls/include \
                 $(CODE_COVERAGE_CFLAGS)

_bpak_la_LIBADD = $(top_builddir)/lib/libbpak.la
_bpak_la_LIBS = $(CODE_COVERAGE_LIBS)
endif
