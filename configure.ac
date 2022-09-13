dnl Bit Packer

AC_PREREQ(2.59)
AC_INIT([bpak], [0.6.0], [Jonas Blixt, <jonpe960@gmail.com>])

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

dnl Python stuff

AC_MSG_CHECKING( wheter to build the bpak python library)
AC_ARG_ENABLE([python-library],
             AS_HELP_STRING([--enable-python-library], [Build the bpak python libraryl]),
             [enable_python_library=$enableval],
             [enable_python_library="no"])

AC_MSG_RESULT($enable_python_library)
AM_CONDITIONAL([BUILD_BPAK_PYTHON_LIB], [test x$enable_python_library = xyes])

if test "x$enable_python_library" = "xyes"; then
    AM_PATH_PYTHON(,, [:])
    AC_ARG_VAR([PYTHON_CONFIG], [python-config program])
    AC_PATH_PROGS([PYTHON_CONFIG], [python$PYTHON_VERSION-config python-config],
                [unknown], [`dirname $PYTHON`:$PATH])
    AC_MSG_CHECKING([for Python include flags])
    if test "x$PYTHON_CONFIG" = "xunknown"; then
      pinc=-I`echo "import distutils.sysconfig; print (distutils.sysconfig.get_python_inc())" | $PYTHON - 2>/dev/null`
      test "x$pinc" = "x-I" && pinc=""
    else
      pinc=`$PYTHON_CONFIG --includes 2>/dev/null`
    fi
    AC_MSG_RESULT([${pinc:-unknown}])
    PYTHON_INCLUDES="$pinc"
    AC_SUBST(PYTHON_INCLUDES)
fi

dnl bpak tool options
AC_ARG_ENABLE([tool],
             AS_HELP_STRING([--disable-tool], [Don''t build the bpak tool]),
             [enable_tool=$enableval],
             [enable_tool="yes"])

AC_MSG_RESULT($enable_tool)
AM_CONDITIONAL([BPAK_BUILD_CLI], [test x$enable_tool = xyes])

if test "x$enable_tool" = "xyes"; then
    PKG_CHECK_MODULES(LIBUUID, [uuid >= 1.0.0])
    AC_SUBST(LIBUUID_CFLAGS)
    AC_SUBST(LIBUUID_LDFLAGS)
    AC_SUBST(LIBUUID_LIBS)
fi

dnl lzma support

AC_ARG_ENABLE([lzma],
             AS_HELP_STRING([--disable-lzma], [Don''t use lzma]),
             [enable_lzma=$enableval],
             [enable_lzma="yes"])

AC_MSG_RESULT($enable_lzma)
AM_CONDITIONAL([BPAK_BUILD_LZMA], [test x$enable_lzma = xyes])

if test "x$enable_lzma" = "xyes"; then
    PKG_CHECK_MODULES(LIBLZMA, [liblzma >= 4.0.0])
    AC_SUBST(LIBLZMA_CFLAGS)
    AC_SUBST(LIBLZMA_LDFLAGS)
    AC_SUBST(LIBLZMA_LIBS)
fi

dnl Enable merkle encoder
AC_ARG_ENABLE([merkle],
             AS_HELP_STRING([--disable-merkle], [Don''t build the bpak merkle encoder]),
             [enable_merkle=$enableval],
             [enable_merkle="yes"])

AM_CONDITIONAL([BPAK_BUILD_MERKLE], [test x$enable_merkle = xyes])

dnl Enable bsdiff
AC_ARG_ENABLE([bsdiff],
             AS_HELP_STRING([--disable-bsdiff], [Don''t build bpak bsdiff]),
             [enable_bsdiff=$enableval],
             [enable_bsdiff="yes"])

AM_CONDITIONAL([BPAK_BUILD_BSDIFF], [test x$enable_bsdiff = xyes])

dnl Enable bspatch
AC_ARG_ENABLE([bspatch],
             AS_HELP_STRING([--disable-bspatch], [Don''t build bpak bspatch]),
             [enable_bspatch=$enableval],
             [enable_bspatch="yes"])

AM_CONDITIONAL([BPAK_BUILD_BSPATCH], [test x$enable_bspatch = xyes])

dnl Enable pkg_create
AC_ARG_ENABLE([pkg-create],
             AS_HELP_STRING([--disable-pkg-create], [Don''t build pkg create]),
             [enable_pkg_create=$enableval],
             [enable_pkg_create="yes"])

AM_CONDITIONAL([BPAK_BUILD_PKG_CREATE], [test x$enable_pkg_create = xyes])

dnl Enable pkg_create
AC_ARG_ENABLE([transport-encode],
             AS_HELP_STRING([--disable-transport-encode], [Don''t build transport encode]),
             [enable_transport_encode=$enableval],
             [enable_transport_encode="yes"])

AM_CONDITIONAL([BPAK_BUILD_TRANSPORT_ENCODE], [test x$enable_transport_encode = xyes])

dnl Enable pkg_sign
AC_ARG_ENABLE([pkg-sign],
             AS_HELP_STRING([--disable-pkg-sign], [Don''t build pkg sign]),
             [enable_pkg_sign=$enableval],
             [enable_pkg_sign="yes"])

AM_CONDITIONAL([BPAK_BUILD_PKG_SIGN], [test x$enable_pkg_sign = xyes])

AC_CONFIG_FILES([Makefile
                src/Makefile
                lib/Makefile
                python/Makefile
                test/Makefile
                lib/bpak.pc])

AX_CODE_COVERAGE

dnl Dependencies build
dnl AC_CONFIG_SUBDIRS([deps/dep1])

AC_OUTPUT
