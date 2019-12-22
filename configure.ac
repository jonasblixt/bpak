dnl Bit Packer

AC_PREREQ(2.59)
AC_INIT([bpak], [0.1.0], [Jonas Blixt, <jonpe960@gmail.com>])

m4_pattern_forbid([^AX_(CHECK_ENABLE_DEBUG|CODE_COVERAGE|COMPILER_FLAGS|COMPILER_FLAGS_(CFLAGS|CXXFLAGS|LDFLAGS))\b],
  [Unexpanded AX_ macro found. Please install GNU autoconf-archive])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

AM_PROG_AR
LT_INIT
AC_PROG_CC

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O

dnl Initialize Libtool

dnl Check if Libtool is present
dnl Libtool is used for building share libraries
AC_PROG_LIBTOOL


dnl bpak tool options
AC_MSG_CHECKING( wheter to build the bpak tool)
AC_ARG_ENABLE([tool],
             AS_HELP_STRING([--disable-tool], [Don''t build the bpak tool]),
             [enable_tool=$enableval],
             [enable_tool="yes"])

AC_MSG_RESULT($enable_tool)
AM_CONDITIONAL([BUILD_BPAK_TOOL], [test x$enable_tool = xyes])

if test "$disable_tool" != "no"; then
    PKG_CHECK_MODULES(UUID, [uuid >= 2.0])
    AC_SUBST(UUID_CFLAGS)
    AC_SUBST(UUID_LIBS)
fi

dnl Crypto backend

AC_MSG_CHECKING(--crypto-backend)
AC_ARG_WITH([cryptoapi],
             AS_HELP_STRING([--with-cryptoapi], [Choose crypto backend]),
             [cryptoapi=$withval],
             [cryptoapi="mbedtls"])

AC_MSG_RESULT($cryptoapi)

AM_CONDITIONAL([CRYPTO_API_MBEDTLS], [test "$cryptoapi" = "mbedtls"])
AM_CONDITIONAL([CRYPTO_API_KCAPI], [test "$cryptoapi" = "kcapi"])

AC_CONFIG_FILES([Makefile
                src/Makefile
                lib/Makefile
                test/Makefile
                lib/bpak.pc])

AX_CODE_COVERAGE

dnl Dependencies build
dnl AC_CONFIG_SUBDIRS([deps/dep1])

AC_OUTPUT
