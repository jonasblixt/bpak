dnl Bit Packer

AC_PREREQ(2.59)
AC_INIT([bpak], [0.1.0], [Jonas Blixt, jonpe960@gmail.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_PROG_CC

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O

dnl Initialize Libtool
LT_INIT

dnl Check if Libtool is present
dnl Libtool is used for building share libraries
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(UUID, [uuid >= 2.0])
PKG_CHECK_MODULES(LZ4, [liblz4])

AC_SUBST(UUID_CFLAGS)
AC_SUBST(UUID_LIBS)

AC_SUBST(LZ4_CFLAGS)
AC_SUBST(LZ4_LIBS)

AC_CONFIG_FILES(Makefile
                src/Makefile
                lib/Makefile
                test/Makefile
                )

dnl Dependencies build
dnl AC_CONFIG_SUBDIRS([deps/dep1])

AC_OUTPUT
