AC_PREREQ([2.61])
AC_INIT([mech_sanon], [1.0], [enquiry@padl.com])
AC_LANG(C)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

dnl AM_INIT_AUTOMAKE([silent-rules])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O
AM_MAINTAINER_MODE()
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static win32-dll])

AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(stdarg.h stdio.h stdint.h sys/param.h stdlib.h)
AC_REPLACE_FUNCS(vasprintf)
AC_CHECK_FUNC(memset_s,
	      AC_DEFINE(HAVE_MEMSET_S, 1,
			[Define if you have the `memset_s' function]))

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_WINDOWS
AX_CHECK_KRB5

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
