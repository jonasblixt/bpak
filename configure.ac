dnl Bit Packer

AC_PREREQ(2.59)
AC_INIT([bpak], [0.5.0], [Jonas Blixt, <jonpe960@gmail.com>])

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
AC_MSG_CHECKING( wheter to build the bpak tool)
AC_ARG_ENABLE([tool],
             AS_HELP_STRING([--disable-tool], [Don''t build the bpak tool]),
             [enable_tool=$enableval],
             [enable_tool="yes"])

AC_MSG_RESULT($enable_tool)
AM_CONDITIONAL([BUILD_BPAK_TOOL], [test x$enable_tool = xyes])


dnl Transport codec options
AC_MSG_CHECKING( wheter to build the bpak transport codecs)
AC_ARG_ENABLE([codecs],
             AS_HELP_STRING([--disable-codecs], [Don''t build the bpak transport codecs]),
             [enable_codecs=$enableval],
             [enable_codecs="yes"])

AC_MSG_RESULT($enable_codecs)
AM_CONDITIONAL([BUILD_BPAK_CODECS], [test x$enable_codecs = xyes])


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
