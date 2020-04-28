AC_PREREQ([2.61])
AC_INIT([mech_sanon], [1.0], [enquiry@padl.com])
AC_LANG(C)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign])
AM_PROG_CC_C_O
AM_MAINTAINER_MODE()
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static win32-dll])

AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(stdarg.h stdio.h stdint.h sys/param.h stdlib.h)
AC_REPLACE_FUNCS(vasprintf)
AC_CHECK_LIB(dl, dlopen, LIBS="$LIBS -ldl",,)

AC_CHECK_FUNC(memset_s,
	      AC_DEFINE(HAVE_MEMSET_S, 1,
			[Define if you have the `memset_s' function]))

#
# -Bsymbolic-functions is necessary to avoid mech_sanon from
# resolving GSS-API functions it implements and calls internally
# in libgssapi_krb5
#
case "${host_os}" in
    linux*)
	LDFLAGS="$LDFLAGS -Wl,-Bsymbolic-functions"
	;;
    *)
	;;
esac

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_KRB5

AC_CONFIG_FILES([Makefile mech-test])
AC_OUTPUT
