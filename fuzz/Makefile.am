bin_PROGRAMS = fuzz1
fuzz1_SOURCES = fuzz_one.c
fuzz1_LDADD = $(top_builddir)/lib/libbpak.la
fuzz1_CFLAGS = -I $(top_srcdir)/include -fsanitize=address,fuzzer
