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
                 test_alg_heatshrink \
                 test_merkle \
                 test_struct_sz \
                 test_meta_align \
                 test_basic_file_io \
                 test_fifo

test_core_meta_SOURCES = test_core_meta.c common.c
test_core_meta_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_core_meta_CFLAGS = $(COMMON_TEST_CFLAGS)

test_core_part_SOURCES = test_core_part.c common.c
test_core_part_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_core_part_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alignment_SOURCES = test_alignment.c common.c
test_alignment_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_alignment_CFLAGS = $(COMMON_TEST_CFLAGS)

test_basic_io_SOURCES = test_basic_io.c common.c
test_basic_io_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_basic_io_CFLAGS = $(COMMON_TEST_CFLAGS)

test_file_ops_SOURCES = test_file_ops.c common.c
test_file_ops_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_file_ops_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alg_heatshrink_SOURCES = test_alg_heatshrink.c common.c
test_alg_heatshrink_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_alg_heatshrink_CFLAGS = $(COMMON_TEST_CFLAGS)

test_merkle_SOURCES = test_merkle.c common.c
test_merkle_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_merkle_CFLAGS = $(COMMON_TEST_CFLAGS)

test_struct_sz_SOURCES = test_struct_sz.c common.c
test_struct_sz_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_struct_sz_CFLAGS = $(COMMON_TEST_CFLAGS)

test_meta_align_SOURCES = test_meta_align.c common.c
test_meta_align_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_meta_align_CFLAGS = $(COMMON_TEST_CFLAGS)

test_basic_file_io_SOURCES = test_basic_file_io.c common.c
test_basic_file_io_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_basic_file_io_CFLAGS = $(COMMON_TEST_CFLAGS)

test_fifo_SOURCES = test_fifo.c common.c
test_fifo_LDADD = libnala.la $(top_builddir)/lib/libbpak.la
test_fifo_CFLAGS = $(COMMON_TEST_CFLAGS)

TESTS = test_core_meta \
        test_core_part \
        test_alignment \
        test_basic_io \
        test_file_ops \
        test_alg_heatshrink \
        test_merkle \
        test_struct_sz \
        test_meta_align \
        test_basic_file_io \
        test_fifo \
        test_create.sh \
        test_transport.sh \
        test_keystore_gen.sh \
        test_signec256.sh \
        test_signec384.sh \
        test_signec521.sh \
        test_generate_id.sh \
        test_sign_openssl.sh \
        test_sign_openssl2.sh \
        test_dep_version.sh \
        test_help_output.sh \
        test_sign_rsa4096.sh \
        test_openssl_resign.sh \
        test_misc.sh \
        test_set_string.sh \
        test_extract.sh \
        test_header_at_the_end.sh \
        test_transport2.sh \
        test_transport3.sh \
        test_transport4.sh \
        test_transport5.sh \
        test_transport6.sh \
        test_sign_dont_hash.sh \
        test_multiple_bsdiff.sh \
        test_openssl_sign.sh

if BUILD_BPAK_PYTHON_LIB
TESTS += test_python_lib_prepare.sh \
         test_python_lib.py \
         test_python_meta_prepare.sh \
         test_python_meta.py \
         test_python_create_package.py \
         test_python_transport_prepare.sh \
         test_python_transport.py

#test_python_create_package.py
endif
