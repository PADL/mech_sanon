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

#include <stdio.h>

static uint8_t anonymous_identity;
gss_name_t
_gss_sanon_anonymous_identity = (gss_name_t)&anonymous_identity;
gss_cred_id_t
_gss_sanon_anonymous_cred = (gss_cred_id_t)&anonymous_identity;

static uint8_t non_anonymous_identity;
gss_name_t
_gss_sanon_non_anonymous_identity = (gss_name_t)&non_anonymous_identity;
gss_cred_id_t
_gss_sanon_non_anonymous_cred = (gss_cred_id_t)&non_anonymous_identity;

static gss_buffer_desc wellknown_user_name = {
    SANON_WELLKNOWN_USER_NAME_LEN,
    SANON_WELLKNOWN_USER_NAME
};
gss_buffer_t
_gss_sanon_wellknown_user_name = &wellknown_user_name;

static gss_buffer_desc wellknown_service_name = {
    SANON_WELLKNOWN_SERVICE_NAME_LEN,
    SANON_WELLKNOWN_SERVICE_NAME
};
gss_buffer_t
_gss_sanon_wellknown_service_name = &wellknown_service_name;

static gss_OID_desc
sanon_mech_oid = { 10, "\x2b\x06\x01\x04\x01\xa9\x4a\x1a\x01\x6e" };

gss_OID GSS_SANON_X25519_MECHANISM = &sanon_mech_oid;

static gss_buffer_desc wellknown_export_name = {
    21,
    "\x04\x01\x00\x0c\x06\x0a\x2b\x06\01\x04\x01\xa9\x4a\x1a\x01\x6e\00\x00\x00\x01\x01"
};
gss_buffer_t
_gss_sanon_wellknown_export_name = &wellknown_export_name;

static void
_gss_sanon_mg_passthru_init(void) __attribute__((constructor));

OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_qop_t,          /* qop_req */
    gss_buffer_t,       /* message_buffer */
    gss_buffer_t) = NULL;      /* message_token */

OM_uint32 KRB5_CALLCONV
(*gss_mg_verify_mic)(
    OM_uint32 *,     /* minor_status */
    gss_ctx_id_t,    /* context_handle */
    gss_buffer_t,    /* message_buffer */
    gss_buffer_t,    /* message_token */
    gss_qop_t *) = NULL;      /* qop_state */

OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,                /* conf_req_flag */
    gss_qop_t,          /* qop_req */
    gss_buffer_t,       /* input_message_buffer */
    int *,              /* conf_state */
    gss_buffer_t) = NULL;      /* output_message_buffer */

OM_uint32 KRB5_CALLCONV
(*gss_mg_unwrap)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_buffer_t,       /* input_message_buffer */
    gss_buffer_t,       /* output_message_buffer */
    int *,              /* conf_state */
    gss_qop_t *) = NULL;       /* qop_state */

OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_size_limit)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,                /* conf_req_flag */
    gss_qop_t,          /* qop_req */
    OM_uint32,          /* req_output_size */
    OM_uint32 *) = NULL;       /* max_input_size */

OM_uint32 KRB5_CALLCONV
(*gss_mg_display_status)(
    OM_uint32 *,        /* minor_status */
    OM_uint32,          /* status_value */
    int,                /* status_type */
    gss_OID,            /* mech_type (used to be const) */
    OM_uint32 *,        /* message_context */
    gss_buffer_t) = NULL;      /* status_string */

OM_uint32 KRB5_CALLCONV
(*gss_mg_inquire_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_name_t *,       /* src_name */
    gss_name_t *,       /* targ_name */
    OM_uint32 *,        /* lifetime_rec */
    gss_OID *,          /* mech_type */
    OM_uint32 *,        /* ctx_flags */
    int *,              /* locally_initiated */
    int *) = NULL;      /* open */

OM_uint32 KRB5_CALLCONV
(*gss_mg_export_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t *,     /* context_handle */
    gss_buffer_t) = NULL;      /* interprocess_token */

OM_uint32 KRB5_CALLCONV
(*gss_mg_import_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_buffer_t,       /* interprocess_token */
    gss_ctx_id_t *) = NULL;    /* context_handle */

OM_uint32 KRB5_CALLCONV
(*gss_mg_delete_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t *,     /* context_handle */
    gss_buffer_t) = NULL;      /* output_token */

OM_uint32 KRB5_CALLCONV
(*gss_mg_pseudo_random)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context */
    int,                /* prf_key */
    const gss_buffer_t, /* prf_in */
    ssize_t,            /* desired_output_len */
    gss_buffer_t) = NULL;      /* prf_out */

OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *,    /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_unwrap_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int *,		/* conf_state */
    gss_qop_t *,	/* qop_state */
    gss_iov_buffer_desc *,    /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_iov_length)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *, /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t,		/* qop_req */
    gss_iov_buffer_desc *, /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic_iov_length)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t,		/* qop_req */
    gss_iov_buffer_desc *, /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_verify_mic_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t *,	/* qop_state */
    gss_iov_buffer_desc *, /* iov */
    int) = NULL;	/* iov_count */

OM_uint32 KRB5_CALLCONV
(*gss_mg_inquire_sec_context_by_oid)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    const gss_OID,	/* desired_object */
    gss_buffer_set_t *) = NULL;	/* data_set */

int
_gss_sanon_mg_available = -1;

#define MG_PASSTHRU_SYM(sym)	do { \
	gss_mg_##sym = dlsym(RTLD_NEXT, "gss_" #sym);	\
	if (gss_mg_##sym == NULL) {			\
	    fprintf(stderr, "mech_sanon is missing symbol for %s\n", "gss_" #sym); \
	    fflush(stderr);				\
	    did_init = 0;				\
	}						\
    } while (0)

static void
_gss_sanon_mg_passthru_init(void)
{
    int did_init = 1;

    MG_PASSTHRU_SYM(get_mic);
    MG_PASSTHRU_SYM(verify_mic);
    MG_PASSTHRU_SYM(wrap);
    MG_PASSTHRU_SYM(unwrap);
    MG_PASSTHRU_SYM(wrap_size_limit);
    MG_PASSTHRU_SYM(display_status);
    MG_PASSTHRU_SYM(inquire_context);
    MG_PASSTHRU_SYM(export_sec_context);
    MG_PASSTHRU_SYM(import_sec_context);
    MG_PASSTHRU_SYM(delete_sec_context);
    MG_PASSTHRU_SYM(pseudo_random);
    MG_PASSTHRU_SYM(wrap_iov);
    MG_PASSTHRU_SYM(unwrap_iov);
    MG_PASSTHRU_SYM(wrap_iov_length);
    MG_PASSTHRU_SYM(get_mic_iov);
    MG_PASSTHRU_SYM(get_mic_iov_length);
    MG_PASSTHRU_SYM(verify_mic_iov);
    MG_PASSTHRU_SYM(inquire_sec_context_by_oid);

    _gss_sanon_mg_available = did_init;
}
