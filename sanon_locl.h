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

#ifndef SANON_LOCL_H
#define SANON_LOCL_H 1

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <errno.h>
#include <assert.h>

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include "x25519_ref10.h"
#include "utils.h"

typedef struct sanon_ctx_desc {
    /* X25519 ECDH secret key */
    uint8_t sk[crypto_scalarmult_curve25519_BYTES];
    /* X25519 ECDH public key */
    uint8_t pk[crypto_scalarmult_curve25519_BYTES];
    /* krb5 context for message protection/PRF */
    gss_ctx_id_t rfc4121;
    unsigned int is_initiator : 1;
} *sanon_ctx;

/* not in a public header */
#ifndef KG_CONTEXT
#define KG_CONTEXT				 (39756040L)
#endif
#ifndef KG_CTX_INCOMPLETE
#define KG_CTX_INCOMPLETE                        (39756039L)
#endif

/* crypto.c */

OM_uint32
_gss_sanon_curve25519_base(OM_uint32 *minor, sanon_ctx sc);

OM_uint32
_gss_sanon_curve25519(OM_uint32 *minor,
		      sanon_ctx sc,
		      gss_buffer_t pk,
		      OM_uint32 req_flags,
		      const gss_channel_bindings_t input_chan_bindings,
		      gss_buffer_t session_key);

OM_uint32
_gss_sanon_import_rfc4121_context(OM_uint32 *minor,
				  sanon_ctx sc,
				  OM_uint32 gss_flags,
				  gss_const_buffer_t session_key);

/* derive.c */
struct krb5_hash_provider {
    char hash_name[8];
    size_t hashsize, blocksize;

    krb5_error_code (*hash)(const krb5_crypto_iov *data, size_t num_data,
                            krb5_data *output);
};

extern struct krb5_hash_provider krb5int_hash_sha256;

krb5_error_code
SP800_108_HMAC(const struct krb5_hash_provider *hash,
	       krb5_key inkey, krb5_data *outrnd,
	       const krb5_data *label, const krb5_data *context);

/* external.c */

extern int _gss_sanon_mg_available;

extern gss_name_t _gss_sanon_anonymous_identity;
extern gss_name_t _gss_sanon_non_anonymous_identity;

extern gss_cred_id_t _gss_sanon_anonymous_cred;
extern gss_cred_id_t _gss_sanon_non_anonymous_cred;

#define SANON_WELLKNOWN_USER_NAME		"WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"
#define SANON_WELLKNOWN_USER_NAME_LEN		(sizeof(SANON_WELLKNOWN_USER_NAME) - 1)

extern gss_buffer_t _gss_sanon_wellknown_user_name;

#define SANON_WELLKNOWN_SERVICE_NAME		"WELLKNOWN@ANONYMOUS"
#define SANON_WELLKNOWN_SERVICE_NAME_LEN	(sizeof(SANON_WELLKNOWN_SERVICE_NAME) - 1)

extern gss_buffer_t _gss_sanon_wellknown_service_name;
extern gss_buffer_t _gss_sanon_wellknown_export_name;

extern gss_OID GSS_SANON_X25519_MECHANISM;

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_qop_t,          /* qop_req */
    gss_buffer_t,       /* message_buffer */
    gss_buffer_t);      /* message_token */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_verify_mic)(
    OM_uint32 *,     /* minor_status */
    gss_ctx_id_t,    /* context_handle */
    gss_buffer_t,    /* message_buffer */
    gss_buffer_t,    /* message_token */
    gss_qop_t *);      /* qop_state */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,                /* conf_req_flag */
    gss_qop_t,          /* qop_req */
    gss_buffer_t,       /* input_message_buffer */
    int *,              /* conf_state */
    gss_buffer_t);      /* output_message_buffer */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_unwrap)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_buffer_t,       /* input_message_buffer */
    gss_buffer_t,       /* output_message_buffer */
    int *,              /* conf_state */
    gss_qop_t *);       /* qop_state */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_size_limit)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,                /* conf_req_flag */
    gss_qop_t,          /* qop_req */
    OM_uint32,          /* req_output_size */
    OM_uint32 *);       /* max_input_size */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_display_status)(
    OM_uint32 *,        /* minor_status */
    OM_uint32,          /* status_value */
    int,                /* status_type */
    gss_OID,            /* mech_type (used to be const) */
    OM_uint32 *,        /* message_context */
    gss_buffer_t);      /* status_string */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_inquire_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context_handle */
    gss_name_t *,       /* src_name */
    gss_name_t *,       /* targ_name */
    OM_uint32 *,        /* lifetime_rec */
    gss_OID *,          /* mech_type */
    OM_uint32 *,        /* ctx_flags */
    int *,              /* locally_initiated */
    int *);             /* open */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_export_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t *,     /* context_handle */
    gss_buffer_t);      /* interprocess_token */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_import_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_buffer_t,       /* interprocess_token */
    gss_ctx_id_t *);    /* context_handle */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_delete_sec_context)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t *,     /* context_handle */
    gss_buffer_t);      /* output_token */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_pseudo_random)(
    OM_uint32 *,        /* minor_status */
    gss_ctx_id_t,       /* context */
    int,                /* prf_key */
    const gss_buffer_t, /* prf_in */
    ssize_t,            /* desired_output_len */
    gss_buffer_t);      /* prf_out */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *,    /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_unwrap_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int *,		/* conf_state */
    gss_qop_t *,	/* qop_state */
    gss_iov_buffer_desc *,    /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_wrap_iov_length)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *, /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t,		/* qop_req */
    gss_iov_buffer_desc *, /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_get_mic_iov_length)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t,		/* qop_req */
    gss_iov_buffer_desc *, /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_verify_mic_iov)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    gss_qop_t *,	/* qop_state */
    gss_iov_buffer_desc *, /* iov */
    int);		/* iov_count */

extern OM_uint32 KRB5_CALLCONV
(*gss_mg_inquire_sec_context_by_oid)(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    const gss_OID,	/* desired_object */
    gss_buffer_set_t *);/* data_set */

/* init_sec_context.c */

int
_gss_sanon_available_p(gss_cred_id_t claimant_cred_handle,
		       const gss_name_t target_name,
		       OM_uint32 req_flags);

/* negoex.c */

#ifdef HAVE_GSS_C_INQ_NEGOEX_KEY
OM_uint32
_gss_sanon_inquire_negoex_key(OM_uint32 *minor,
			      const sanon_ctx sc,
			      gss_const_OID desired_object,
			      gss_buffer_set_t *data_set);
#endif /* HAVE_GSS_C_INQ_NEGOEX_KEY */

/* rfc4121.c */
OM_uint32
_gss_mg_import_rfc4121_context(OM_uint32 *minor,
			       int is_initiator,
			       OM_uint32 flags,
			       krb5_enctype etype,
			       gss_const_buffer_t session_key,
			       gss_ctx_id_t *ctx);

/* flags that are valid to be sent from a SAnon initiator in the flags field */
#define SANON_PROTOCOL_FLAG_MASK ( GSS_C_DCE_STYLE | GSS_C_IDENTIFY_FLAG | GSS_C_EXTENDED_ERROR_FLAG )

#endif /* SANON_LOCL_H */
