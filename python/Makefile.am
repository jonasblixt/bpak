if BUILD_BPAK_PYTHON_LIB

bpakdir = $(pkgpythondir)
bpak_PYTHON = bpak/package.py \
              bpak/utils.py \
              bpak/__init__.py

pyexec_LTLIBRARIES = _bpak.la

_bpak_la_SOURCES = package.c

_bpak_la_LDFLAGS = -avoid-version -module
_bpak_la_CFLAGS = -I$(PYTHON_INCLUDES) \
                 -I$(top_srcdir)/include \
                 -I$(top_srcdir)/src \
                 $(CODE_COVERAGE_CFLAGS)

_bpak_la_LIBADD = $(top_builddir)/lib/libbpak.la -lmbedtls -lmbedcrypto
_bpak_la_LIBS = $(CODE_COVERAGE_LIBS)
endif
