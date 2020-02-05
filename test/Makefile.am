COMMON_TEST_CFLAGS = -I $(top_srcdir)/include \
					 -I $(top_srcdir)/lib \
					 -fsanitize=address

check_LTLIBRARIES = libnala.la

libnala_la_SOURCES = nala.c

check_PROGRAMS = test_core_meta \
				 test_core_part \
				 test_alignment \
				 test_basic_io \
				 test_file_ops \
				 test_crypto \
				 test_alg_heatshrink \
				 test_merkle \
				 test_struct_sz \
				 test_meta_align

test_core_meta_SOURCES = test_core_meta.c
test_core_meta_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_core_meta_CFLAGS = $(COMMON_TEST_CFLAGS)

test_core_part_SOURCES = test_core_part.c
test_core_part_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_core_part_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alignment_SOURCES = test_alignment.c
test_alignment_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_alignment_CFLAGS = $(COMMON_TEST_CFLAGS)

test_basic_io_SOURCES = test_basic_io.c
test_basic_io_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_basic_io_CFLAGS = $(COMMON_TEST_CFLAGS)

test_file_ops_SOURCES = test_file_ops.c
test_file_ops_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_file_ops_CFLAGS = $(COMMON_TEST_CFLAGS)

test_crypto_SOURCES = test_crypto.c
test_crypto_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_crypto_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alg_heatshrink_SOURCES = test_alg_heatshrink.c
test_alg_heatshrink_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_alg_heatshrink_CFLAGS = $(COMMON_TEST_CFLAGS)

test_merkle_SOURCES = test_merkle.c
test_merkle_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_merkle_CFLAGS = $(COMMON_TEST_CFLAGS)

test_struct_sz_SOURCES = test_struct_sz.c
test_struct_sz_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_struct_sz_CFLAGS = $(COMMON_TEST_CFLAGS)

test_meta_align_SOURCES = test_meta_align.c
test_meta_align_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_meta_align_CFLAGS = $(COMMON_TEST_CFLAGS)

TESTS = test_core_meta \
		test_core_part \
		test_alignment \
		test_basic_io \
		test_file_ops \
		test_crypto \
		test_alg_heatshrink \
		test_merkle \
		test_struct_sz \
		test_meta_align \
		test_create.sh


