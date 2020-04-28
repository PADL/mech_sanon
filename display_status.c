/*
 * Copyright (c) 1998 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "sanon_locl.h"

OM_uint32 GSSAPI_CALLCONV
gss_display_status(OM_uint32 *minor,
		   OM_uint32 status_value,
		   int status_type,
		   const gss_OID mech_type,
		   OM_uint32 *message_context __attribute__((__unused__)),
		   gss_buffer_t status_string)
{
    OM_uint32 major = GSS_S_FAILURE;
    krb5_context context;

    status_string->length = 0;
    status_string->value = NULL;

    if (gss_oid_equal(mech_type, GSS_C_NO_OID) == 0 &&
	gss_oid_equal(mech_type, GSS_SANON_X25519_MECHANISM) == 0) {
	*minor = 0;
	return GSS_S_BAD_MECH;
    }

    if (status_type != GSS_C_MECH_CODE) {
	*minor = EINVAL;
	return GSS_S_BAD_STATUS;
    }

    /* calling into mechglue seems to infinite loop, so */
    *minor = krb5_init_context(&context);
    if (*minor == 0) {
	const char *error = krb5_get_error_message(context, status_value);

	if (error) {
	    major = make_string_buffer(minor, error, status_string);
	    krb5_free_error_message(context, error);
	}
    }

    krb5_free_context(context);

    return major;
}
