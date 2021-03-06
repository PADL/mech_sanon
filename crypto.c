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
gss_wrap(OM_uint32 *minor,
	 gss_ctx_id_t context_handle,
	 int conf_req_flag,
	 gss_qop_t qop_req,
	 gss_buffer_t input_message_buffer,
	 int *conf_state,
	 gss_buffer_t output_message_buffer)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_wrap(minor, sc->rfc4121,
		       conf_req_flag, qop_req,
		       input_message_buffer, conf_state,
		       output_message_buffer);
}

OM_uint32 GSSAPI_CALLCONV
gss_wrap_size_limit(OM_uint32 *minor,
		    gss_ctx_id_t context_handle,
		    int conf_req_flag,
		    gss_qop_t qop_req,
		    OM_uint32 req_output_size,
		    OM_uint32 *max_input_size)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_wrap_size_limit(minor, sc->rfc4121,
				  conf_req_flag, qop_req,
				  req_output_size, max_input_size);
}

OM_uint32 GSSAPI_CALLCONV
gss_wrap_iov(OM_uint32 *minor,
	     gss_ctx_id_t context_handle,
	     int conf_req_flag,
	     gss_qop_t qop_req,
	     int *conf_state,
	     gss_iov_buffer_desc *iov,
	     int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_wrap_iov(minor, sc->rfc4121,
			   conf_req_flag, qop_req,
			   conf_state, iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
gss_wrap_iov_length(OM_uint32 *minor,
		    gss_ctx_id_t context_handle,
		    int conf_req_flag,
		    gss_qop_t qop_req,
		    int *conf_state,
		    gss_iov_buffer_desc *iov,
		    int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_wrap_iov_length(minor, sc->rfc4121,
				  conf_req_flag, qop_req,
				  conf_state, iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
gss_unwrap(OM_uint32 *minor,
	   gss_ctx_id_t context_handle,
	   const gss_buffer_t input_message_buffer,
	   gss_buffer_t output_message_buffer,
	   int *conf_state,
	   gss_qop_t * qop_state)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_unwrap(minor, sc->rfc4121,
			 input_message_buffer, output_message_buffer,
			 conf_state, qop_state);
}

OM_uint32 GSSAPI_CALLCONV
gss_unwrap_iov(OM_uint32 *minor,
	       gss_ctx_id_t context_handle,
	       int *conf_state,
	       gss_qop_t *qop_state,
	       gss_iov_buffer_desc *iov,
	       int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_unwrap_iov(minor, sc->rfc4121,
			     conf_state, qop_state,
			     iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
gss_get_mic(OM_uint32 *minor,
	    gss_ctx_id_t context_handle,
	    gss_qop_t qop_req,
	    const gss_buffer_t message_buffer,
	    gss_buffer_t message_token)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_get_mic(minor, sc->rfc4121,
			  qop_req, message_buffer,
			  message_token);
}

OM_uint32 GSSAPI_CALLCONV
gss_verify_mic(OM_uint32 *minor,
	       gss_ctx_id_t context_handle,
	       const gss_buffer_t message_buffer,
	       const gss_buffer_t token_buffer,
	       gss_qop_t *qop_state)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_verify_mic(minor, sc->rfc4121,
			     message_buffer, token_buffer,
			     qop_state);
}

OM_uint32 GSSAPI_CALLCONV
gss_pseudo_random(OM_uint32 *minor,
		  gss_ctx_id_t context_handle,
		  int prf_key,
		  const gss_buffer_t prf_in,
		  ssize_t desired_output_len,
		  gss_buffer_t prf_out)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_pseudo_random(minor, sc->rfc4121,
				prf_key, prf_in, desired_output_len,
				prf_out);
}

OM_uint32 GSSAPI_CALLCONV
gss_get_mic_iov(OM_uint32 *minor,
		gss_ctx_id_t context_handle,
		gss_qop_t qop_req,
		gss_iov_buffer_desc *iov,
		int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_get_mic_iov(minor, sc->rfc4121,
			      qop_req, iov, iov_count);
}

OM_uint32 GSSAPI_CALLCONV
gss_get_mic_iov_length(OM_uint32 *minor,
		       gss_ctx_id_t context_handle,
		       gss_qop_t qop_req,
		       gss_iov_buffer_desc *iov,
		       int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_get_mic_iov_length(minor, sc->rfc4121,
				     qop_req, iov, iov_count);
}

OM_uint32 KRB5_CALLCONV
gss_verify_mic_iov(OM_uint32 *minor,
		   gss_ctx_id_t context_handle,
		   gss_qop_t *qop_state,
		   gss_iov_buffer_desc *iov,
		   int iov_count)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    return gss_mg_verify_mic_iov(minor, sc->rfc4121,
				 qop_state, iov, iov_count);
}

/*
 * Generate a curve25519 secret and public key
 */

OM_uint32
_gss_sanon_curve25519_base(OM_uint32 *minor, sanon_ctx sc)
{
    krb5_data data;
    krb5_error_code ret;

    data.data = (char *)sc->sk;
    data.length = crypto_scalarmult_curve25519_BYTES;

    ret = krb5_c_random_make_octets(NULL, &data);
    if (ret) {
	*minor = ret;
	return GSS_S_FAILURE;
    }

    if (crypto_scalarmult_curve25519_base(sc->pk, sc->sk) != 0) {
	*minor = EINVAL;
	return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

/*
 * Derive the context session key using SP800-108 KDF in HMAC mode
 * and the public keys and channel binding data.
 */

OM_uint32
_gss_sanon_curve25519(OM_uint32 *minor,
		      sanon_ctx sc,
		      gss_buffer_t pk,
		      OM_uint32 gss_flags,
		      const gss_channel_bindings_t input_chan_bindings,
		      gss_buffer_t session_key)
{
    uint8_t shared[crypto_scalarmult_curve25519_BYTES];
    uint8_t *p;
    krb5_error_code ret;
    krb5_context context;
    krb5_data kdf_label, kdf_context, keydata;
    krb5_keyblock kdf_K1;
    krb5_key kdf_K1_key = NULL;

    session_key->length = 0;
    session_key->value = NULL;

    if (pk == GSS_C_NO_BUFFER || pk->length != crypto_scalarmult_curve25519_BYTES)
	return GSS_S_DEFECTIVE_TOKEN;

    if (crypto_scalarmult_curve25519(shared, sc->sk, pk->value) != 0)
	return GSS_S_FAILURE;

    ret = krb5_init_context(&context);
    if (ret != 0)
	goto out;

    kdf_K1.magic = KV5M_KEYBLOCK;
    kdf_K1.enctype = ENCTYPE_AES128_CTS_HMAC_SHA256_128; /* XXX */
    kdf_K1.length = sizeof(shared);
    kdf_K1.contents = shared;

    ret = krb5_k_create_key(context, &kdf_K1, &kdf_K1_key);
    if (ret != 0)
	goto out;

    kdf_label.length = sizeof("sanon-x25519") - 1;
    kdf_label.data = "sanon-x25519";

    ret = alloc_data(&kdf_context,
		     2 * crypto_scalarmult_curve25519_BYTES + 8 +
		     (input_chan_bindings ? input_chan_bindings->application_data.length : 0));
    if (ret != 0)
	goto out;

    p = (uint8_t *)kdf_context.data;

    if (sc->is_initiator) {
	memcpy(p, sc->pk, sizeof(sc->pk));
	memcpy(&p[pk->length], pk->value, pk->length);
    } else {
	memcpy(p, pk->value, pk->length);
	memcpy(&p[sizeof(sc->pk)], sc->pk, sizeof(sc->pk));
    }
    p += 2 * crypto_scalarmult_curve25519_BYTES;
    encode_be_uint32(0, p); /* upper 32 bits presently unused */
    p += 4;
    encode_be_uint32(gss_flags, p);
    p += 4;

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS &&
	input_chan_bindings->application_data.value != NULL) {
	memcpy(p, input_chan_bindings->application_data.value,
	       input_chan_bindings->application_data.length);
    }

    ret = alloc_data(&keydata, 16);
    if (ret != 0)
	goto out;

    ret = SP800_108_HMAC(&krb5int_hash_sha256, kdf_K1_key,
			 &keydata, &kdf_label, &kdf_context);
    if (ret != 0)
	goto out;

    session_key->length = keydata.length;
    session_key->value = keydata.data;

    keydata.length = 0;
    keydata.data = NULL;

out:
    secure_zero_memory(kdf_context.data, kdf_context.length);
    krb5_free_data_contents(context, &kdf_context);
    krb5_free_data_contents(context, &keydata);

    if (kdf_K1_key != NULL)
	krb5_k_free_key(context, kdf_K1_key);
    if (context)
	krb5_free_context(context);

    secure_zero_memory(shared, sizeof(shared));

    *minor = ret;
    return ret != 0 ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32
_gss_sanon_import_rfc4121_context(OM_uint32 *minor,
				  sanon_ctx sc,
				  OM_uint32  gss_flags,
				  gss_const_buffer_t session_key)
{
    return _gss_mg_import_rfc4121_context(minor, sc->is_initiator, gss_flags,
                                          ENCTYPE_AES128_CTS_HMAC_SHA256_128,
                                          session_key, &sc->rfc4121);
}
