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

OM_uint32 GSSAPI_CALLCONV
gss_import_sec_context(OM_uint32 *minor,
		       gss_buffer_t interprocess_token,
		       gss_ctx_id_t *context_handle)
{
    OM_uint32 major;
    sanon_ctx sc;

    *context_handle = GSS_C_NO_CONTEXT;

    /* this checks the mechglue library was loaded properly */
    if (!_gss_sanon_available_p(GSS_C_NO_CREDENTIAL,
				GSS_C_NO_NAME, GSS_C_ANON_FLAG)) {
	*minor = 0;
	return GSS_S_UNAVAILABLE;
    }

    sc = calloc(1, sizeof(*sc));
    if (sc == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    major = gss_mg_import_sec_context(minor, interprocess_token,
				      &sc->rfc4121);
    if (major != GSS_S_COMPLETE) {
	free(sc);
	return major;
    }

    *context_handle = (gss_ctx_id_t)sc;
    return GSS_S_COMPLETE;
}
