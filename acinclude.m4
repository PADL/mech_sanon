dnl BSD 3-Clause License
dnl 
dnl Copyright (c) 2019, Jisc
dnl All rights reserved.
dnl 
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions are met:
dnl 
dnl * Redistributions of source code must retain the above copyright notice, this
dnl   list of conditions and the following disclaimer.
dnl 
dnl * Redistributions in binary form must reproduce the above copyright notice,
dnl   this list of conditions and the following disclaimer in the documentation
dnl   and/or other materials provided with the distribution.
dnl 
dnl * Neither the name of the copyright holder nor the names of its
dnl   contributors may be used to endorse or promote products derived from
dnl   this software without specific prior written permission.
dnl 
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
dnl AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
dnl DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
dnl FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
dnl DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
dnl SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
dnl CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
dnl OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
dnl OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
dnl 

AC_DEFUN([AX_CHECK_KRB5],
[AC_MSG_CHECKING(for GSS-API and Kerberos implementation)
KRB5_DIR=
found_krb5="no"
AC_ARG_WITH(krb5,
    AC_HELP_STRING([--with-krb5],
       [Use krb5 (in specified installation directory)]),
    [check_krb5_dir="$withval"],
    [check_krb5_dir=])
for dir in $check_krb5_dir $prefix /usr/local /usr ; do
   krb5dir="$dir"
   if test -x "$dir/bin/krb5-config"; then
     found_krb5="yes";
     if test "x$target_windows" = "xyes"; then
        KRB5_CFLAGS=-I"$check_krb5_dir/include";
        KRB5_LDFLAGS="-L$check_krb5_dir/lib/";
        KRB5_LIBS="-lkrb5_32 -lgssapi32";
        COMPILE_ET="$check_krb5_dir/bin/compile_et";
	AC_MSG_RESULT([yes])
     else
        KRB5_CFLAGS=`$dir/bin/krb5-config gssapi --cflags`;
        KRB5_LDFLAGS="-L$dir/lib";
        KRB5_LIBS=`$dir/bin/krb5-config gssapi --libs`
AC_MSG_RESULT([yes])
        AC_PATH_PROG(COMPILE_ET, [compile_et], [compile_et], [$dir/bin$PATH_SEPARATOr])
     fi
     break;
   fi
done
if test x_$found_krb5 != x_yes; then
   AC_MSG_RESULT($found_krb5)
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find GSS-API/Kerberos libraries.

  Please install MIT or Heimdal or specify installation directory with
  --with-krb5=(dir).
----------------------------------------------------------------------
])
else
	printf "Kerberos found in $krb5dir\n";
	AC_SUBST(COMPILE_ET)
	AC_CHECK_LIB(krb5, GSS_C_NT_COMPOSITE_EXPORT, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_NT_COMPOSITE_EXPORT], 1, [Define if GSS-API library supports recent naming extensions draft])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, GSS_C_MA_NEGOEX_AND_SPNEGO, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_MA_NEGOEX_AND_SPNEGO], 1, [Define if GSS-API library supports exposing mechanism through both NegoEx and SPNEGO])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, __gss_c_ma_negoex_and_spnego_oid_desc, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_MA_NEGOEX_AND_SPNEGO], 1, [Define if GSS-API library supports exposing mechanism through both NegoEx and SPNEGO])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_inquire_attrs_for_mech, [AC_DEFINE_UNQUOTED([HAVE_GSS_INQUIRE_ATTRS_FOR_MECH], 1, [Define if GSS-API library supports RFC 5587])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_krb5_import_cred, [AC_DEFINE_UNQUOTED([HAVE_GSS_KRB5_IMPORT_CRED], 1, [Define if GSS-API library supports gss_krb5_import_cred])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, heimdal_version, [AC_DEFINE_UNQUOTED([HAVE_HEIMDAL_VERSION], 1, [Define if building against Heimdal Kerberos implementation]) heimdal=yes], [heimdal=no], "$KRB5_LIBS")
	AM_CONDITIONAL(HEIMDAL, test "x$heimdal" != "xno")
	AM_CONDITIONAL(BUILD_ON_MACOS, test "x$building_on_macos" != "xno")
	AC_CHECK_TYPE(gss_const_name_t, [AC_DEFINE([MECHEAP_GSS_CONST_NAME_T_IS_POINTER], 1, [Define if gss_const_name_t is a pointer. Broken krb5 10.x headers define it as a struct.])], [], [[#include <gssapi/gssapi.h>]])
	# We're building with Heimdal
	if test "x$heimdal" != "xno"; then
		# we're on macOS - Build against the GSS and Heimdal frameworks instead
		if test "x$building_on_macos" != "xno" ; then
			KRB5_LDFLAGS=" ";
			KRB5_LIBS=" -framework GSS -F/System/Library/PrivateFrameworks -framework Heimdal "
		fi
	fi
	AC_SUBST(KRB5_CFLAGS)
	AC_SUBST(KRB5_LDFLAGS)
	AC_SUBST(KRB5_LIBS)
fi
])dnl

