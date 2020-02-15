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
				mbedtls/pk.c \
				mbedtls/pem.c \
				mbedtls/rsa.c \
				mbedtls/rsa_internal.c \
				mbedtls/ecdsa.c \
				mbedtls/platform.c \
				mbedtls/platform_util.c \
				mbedtls/asn1parse.c \
				mbedtls/asn1write.c \
				mbedtls/bignum.c \
				mbedtls/ecp.c \
				mbedtls/ecp_curves.c \
				mbedtls/hmac_drbg.c \
				mbedtls/md.c \
				mbedtls/md_wrap.c \
				mbedtls/sha256.c \
				mbedtls/ripemd160.c \
				mbedtls/md5.c \
				mbedtls/sha1.c \
				mbedtls/base64.c \
				mbedtls/oid.c \
				mbedtls/pk_wrap.c \
				mbedtls/pkparse.c \
				mbedtls/pkcs12.c \
				mbedtls/cipher.c \
				mbedtls/gcm.c \
				mbedtls/aesni.c \
				mbedtls/ccm.c \
				mbedtls/chachapoly.c \
				mbedtls/poly1305.c \
				mbedtls/chacha20.c \
				mbedtls/cipher_wrap.c \
				mbedtls/aes.c \
				mbedtls/arc4.c \
				mbedtls/blowfish.c \
				mbedtls/camellia.c \
				mbedtls/des.c \
				mbedtls/entropy.c \
				mbedtls/pkwrite.c \
				mbedtls/ctr_drbg.c \
				mbedtls/pkcs5.c \
				mbedtls/entropy_poll.c \
				mbedtls/timing.c


bpak_CFLAGS  = -I$(top_srcdir)/include \
			   -I$(top_srcdir)/src/mbedtls/include \
				$(CODE_COVERAGE_CFLAGS) \
				$(UUID_CFLAGS)

bpak_LDFLAGS =
bpak_LIBS = $(CODE_COVERAGE_LIBS)

bpak_LDADD = $(top_builddir)/lib/libbpak.la $(UUID_LIBS)

endif
