/*
 * Copyright (c) 2019-2020, AuriStor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sanon_locl.h"

static int
is_anonymous_identity_p(gss_buffer_t name_string, gss_OID name_type)
{
    if (gss_oid_equal(name_type, GSS_C_NT_ANONYMOUS))
	return TRUE;
    else if ((gss_oid_equal(name_type, GSS_C_NT_USER_NAME) ||
	      gss_oid_equal(name_type, GSS_KRB5_NT_PRINCIPAL_NAME)) &&
	buffer_equal_p(name_string, _gss_sanon_wellknown_user_name))
	return TRUE;
    else if (gss_oid_equal(name_type, GSS_C_NT_HOSTBASED_SERVICE) &&
	buffer_equal_p(name_string, _gss_sanon_wellknown_service_name))
	return TRUE;
    else if (gss_oid_equal(name_type, GSS_C_NT_EXPORT_NAME) &&
	buffer_equal_p(name_string, _gss_sanon_wellknown_export_name))
	return TRUE;

    return FALSE;
}

OM_uint32 GSSAPI_CALLCONV
gss_import_name(OM_uint32 *minor,
		gss_buffer_t input_name_buffer,
		gss_OID input_name_type,
		gss_name_t *output_name)
{
    int is_anonymous;

    if (input_name_type == GSS_C_NO_OID)
	input_name_type = GSS_C_NT_USER_NAME; /* matches Heimdal */

    *minor = 0;
    is_anonymous = is_anonymous_identity_p(input_name_buffer, input_name_type);

    if (gss_oid_equal(input_name_type, GSS_C_NT_EXPORT_NAME) &&
	is_anonymous == FALSE) {
	/* can't import non-anonymous names */
	*output_name = GSS_C_NO_NAME;
	return GSS_S_BAD_NAME;
    }

    *output_name = is_anonymous ? _gss_sanon_anonymous_identity
				: _gss_sanon_non_anonymous_identity;

    return GSS_S_COMPLETE;
}
