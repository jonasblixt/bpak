if BUILD_BPAK_PYTHON_LIB

pyexec_LTLIBRARIES = bpak.la

bpak_la_SOURCES = package.c
bpak_la_LDFLAGS = -avoid-version -module
bpak_la_CFLAGS = -I$(PYTHON_INCLUDES) \
				 -I$(top_srcdir)/include

bpak_la_LIBADD = $(top_builddir)/lib/libbpak.la

endif
