COMMON_TEST_CFLAGS = -I $(top_srcdir)/include \
                     -I $(top_srcdir)/lib \
                     -fsanitize=address
COMMON_TEST_LDADD = libnala.la $(top_builddir)/lib/libbpak.la -lmbedtls -lmbedcrypto
check_LTLIBRARIES = libnala.la

libnala_la_SOURCES = nala.c

check_PROGRAMS = test_core_meta \
                 test_bsdiff_hs \
                 test_bsdiff \
                 test_merkle \
                 test_core_part \
                 test_alignment \
                 test_alg_heatshrink \
                 test_struct_sz \
                 test_meta_align

test_core_meta_SOURCES = test_core_meta.c common.c
test_core_meta_LDADD = $(COMMON_TEST_LDADD) 
test_core_meta_CFLAGS = $(COMMON_TEST_CFLAGS)

test_bsdiff_hs_SOURCES = test_bsdiff_hs.c common.c
test_bsdiff_hs_LDADD = $(COMMON_TEST_LDADD)
test_bsdiff_hs_CFLAGS = $(COMMON_TEST_CFLAGS)

test_bsdiff_SOURCES = test_bsdiff.c common.c
test_bsdiff_LDADD = $(COMMON_TEST_LDADD)
test_bsdiff_CFLAGS = $(COMMON_TEST_CFLAGS)

test_core_part_SOURCES = test_core_part.c common.c
test_core_part_LDADD = $(COMMON_TEST_LDADD)
test_core_part_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alignment_SOURCES = test_alignment.c common.c
test_alignment_LDADD = $(COMMON_TEST_LDADD)
test_alignment_CFLAGS = $(COMMON_TEST_CFLAGS)

test_alg_heatshrink_SOURCES = test_alg_heatshrink.c common.c
test_alg_heatshrink_LDADD = $(COMMON_TEST_LDADD)
test_alg_heatshrink_CFLAGS = $(COMMON_TEST_CFLAGS)

test_merkle_SOURCES = test_merkle.c common.c
test_merkle_LDADD = $(COMMON_TEST_LDADD)
test_merkle_CFLAGS = $(COMMON_TEST_CFLAGS)

test_struct_sz_SOURCES = test_struct_sz.c common.c
test_struct_sz_LDADD = $(COMMON_TEST_LDADD)
test_struct_sz_CFLAGS = $(COMMON_TEST_CFLAGS)

test_meta_align_SOURCES = test_meta_align.c common.c
test_meta_align_LDADD = $(COMMON_TEST_LDADD)
test_meta_align_CFLAGS = $(COMMON_TEST_CFLAGS)

TESTS = test_core_meta \
        test_core_part \
        test_alignment \
        test_struct_sz \
        test_meta_align \
        test_merkle \
        test_create.sh \
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
        test_transport.sh \
        test_transport5.sh \
        test_transport6.sh \
        test_sign_dont_hash.sh \
        test_multiple_bsdiff.sh \
        test_openssl_sign.sh \
        test_bsdiff_hs \
        test_bsdiff \
        test_corrupt_payload.sh \
        test_corrupt_payload2.sh \
        test_corrupt_header.sh \
        test_corrupt_merkle_tree.sh

if BUILD_BPAK_PYTHON_LIB
TESTS += test_python_lib.py \
         test_python_meta.py \
         test_python_create_package.py \
         test_python_transport.py
endif
