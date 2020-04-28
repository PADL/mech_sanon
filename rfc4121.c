/* lib/gssapi/krb5/ser_sctx.c - [De]serialization of security context */
/*
 * Copyright 1995, 2004, 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "sanon_locl.h"
#include "mit-serialization.h"

static krb5_error_code
rfc4121_oid_externalize(gss_OID oid,
			uint8_t **buffer,
			size_t *lenremain)
{
    krb5_error_code ret;

    ret = krb5_ser_pack_int32(KV5M_GSS_OID, buffer, lenremain);
    if (ret)
	return ret;
    ret = krb5_ser_pack_int32((int32_t) oid->length,
			      buffer, lenremain);
    if (ret)
	return ret;
    ret = krb5_ser_pack_bytes((uint8_t *) oid->elements,
			      oid->length, buffer, lenremain);
    if (ret)
	return ret;

    return krb5_ser_pack_int32(KV5M_GSS_OID, buffer, lenremain);
}

static krb5_error_code
rfc4121_oid_size(gss_OID oid, size_t *sizep)
{
    krb5_error_code ret;
    size_t required;

    ret = EINVAL;
    if (oid != NULL) {
	required = 2 * sizeof(int32_t); /* For the header and trailer */
	required += sizeof(int32_t);
	required += oid->length;

	ret = 0;

	*sizep += required;
    }

    return(ret);
}

static void
g_seqstate_size(g_seqnum_state state, size_t *sizep)
{
    *sizep += sizeof(*state);
}

static krb5_error_code
g_seqstate_externalize(g_seqnum_state state,
		       unsigned char **buf,
		       size_t *lenremain)
{
    if (*lenremain < sizeof(*state))
	return ENOMEM;

    memcpy(*buf, state, sizeof(*state));
    *buf += sizeof(*state);
    *lenremain -= sizeof(*state);

    return 0;
}

static krb5_error_code
rfc4121_seqstate_externalize(g_seqnum_state arg,
			     uint8_t **buffer,
			     size_t *lenremain)
{
    krb5_error_code err;

    err = krb5_ser_pack_int32(KV5M_GSS_QUEUE, buffer, lenremain);
    if (err == 0)
	err = g_seqstate_externalize(arg, buffer, lenremain);
    if (err == 0)
	err = krb5_ser_pack_int32(KV5M_GSS_QUEUE, buffer, lenremain);

    return err;
}

static krb5_error_code
rfc4121_seqstate_size(g_seqnum_state arg, size_t *sizep)
{
    krb5_error_code ret;
    size_t required;

    ret = EINVAL;
    if (arg) {
	required = 2 * sizeof(int32_t); /* For the header and trailer */
	g_seqstate_size(arg, &required);

	ret = 0;
	*sizep += required;
    }

    return ret;
}

static uint8_t seed[16];

/*
 * Determine the size required for this krb5_gss_ctx_id_rec.
 */
static krb5_error_code
rfc4121_ctx_size(krb5_context kcontext,
		 gss_OID mech_used,
		 krb5_principal dummy_principal,
		 g_seqnum_state seqstate,
		 krb5_auth_context dummy_auth_context,
		 krb5_keyblock *acceptor_subkey,
		 krb5_authdata_context dummy_authdata_context,
		 size_t *sizep)
{
    krb5_error_code     ret;
    size_t	      required;

    /*
     * GSS exported context token requires:
     *  int32_t	for mech_used->length
     *  ...		for mech_used
     * krb5_gss_ctx_id_rec requires:
     *  int32_t		for KG_CONTEXT
     *  int32_t		for initiate.
     *  int32_t		for established.
     *  int32_t		for have_acceptor_subkey.
     *  int32_t		for seed_init.
     *  int32_t		for gss_flags.
     *  sizeof(seed)    for seed
     *  ...		for here
     *  ...		for there
     *  ...		for subkey
     *  int32_t		for signalg.
     *  int32_t		for cksum_size.
     *  int32_t		for sealalg.
     *  ...		for enc
     *  ...		for seq
     *  int32_t		for authtime.
     *  int32_t		for starttime.
     *  int32_t		for endtime.
     *  int32_t		for renew_till.
     *  int32_t		for flags.
     *  int64_t		for seq_send.
     *  int64_t		for seq_recv.
     *  ...		for seqstate
     *  ...		for auth_context
     *  ...		for mech_used
     *  int32_t		for proto
     *  int32_t		for cksumtype
     *  ...		for acceptor_subkey
     *  int32_t		for acceptor_key_cksumtype
     *  int32_t		for cred_rcache
     *  int32_t		for number of elements in authdata array
     *  ...		for authdata array
     *  int32_t		for trailer.
     */
    ret = EINVAL;
    required = 4 + mech_used->length;
    required += 2 * sizeof(int32_t);
    required += 2 * sizeof(int64_t);
    required += sizeof(seed);

    ret = 0;

    if (!ret)
	ret = rfc4121_oid_size(mech_used, &required);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_PRINCIPAL,
			       dummy_principal, &required);
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_PRINCIPAL,
			       dummy_principal, &required);
#else
    if (!ret)
	ret = k5_size_principal(dummy_principal, &required);
    if (!ret)
	ret = k5_size_principal(dummy_principal, &required);
#endif
    if (!ret)
	ret = rfc4121_seqstate_size(seqstate, &required);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_CONTEXT,
			       kcontext, &required);
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_AUTH_CONTEXT,
			       dummy_auth_context, &required);
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_KEYBLOCK,
			       acceptor_subkey, &required);
    if (!ret)
	ret = krb5_size_opaque(kcontext, KV5M_AUTHDATA_CONTEXT,
			       dummy_authdata_context, &required);
#else
    if (!ret)
	ret = k5_size_context(kcontext, &required);
    if (!ret)
	ret = k5_size_auth_context(dummy_auth_context, &required);
    if (!ret)
	ret = k5_size_keyblock(acceptor_subkey, &required);
    if (!ret)
	ret = k5_size_authdata_context(kcontext, dummy_authdata_context, &required);
#endif
    *sizep += required;

    return(ret);
}

/*
 * Externalize this krb5_gss_ctx_id_ret.
 */
static krb5_error_code
rfc4121_ctx_externalize(krb5_context kcontext,
			int is_initiator,
			OM_uint32 gss_flags,
			gss_OID mech_used,
			krb5_principal dummy_principal,
			g_seqnum_state seqstate,
			krb5_cksumtype cksumtype,
			krb5_auth_context dummy_auth_context,
			krb5_keyblock *acceptor_subkey,
			krb5_authdata_context dummy_authdata_context,
			gss_buffer_t token)

{
    krb5_error_code ret;
    uint8_t *bp;
    size_t remain;

    ret = rfc4121_ctx_size(kcontext, gss_mech_krb5, dummy_principal,
			    seqstate, dummy_auth_context, acceptor_subkey,
			    dummy_authdata_context, &token->length);
    if (ret)
	return ret;

    bp = token->value = calloc(1, token->length);
    if (token->value == NULL)
	return ENOMEM;

    remain = token->length;
    ret = ENOMEM;

    {
	/* GSS token framing */
	ret = krb5_ser_pack_int32(mech_used->length, &bp, &remain);
	if (!ret)
	    ret = krb5_ser_pack_bytes(mech_used->elements, mech_used->length,
				       &bp, &remain);

	/* Our identifier */
	(void) krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);

	/* Now static data */
	(void) krb5_ser_pack_int32((int32_t) is_initiator,
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 1, /* established */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 1, /* have_acceptor_subkey */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0, /* seed_init */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) gss_flags,
				   &bp, &remain);
	(void) krb5_ser_pack_bytes(seed, sizeof(seed),
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0xFFFF, /* signalg */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0, /* cksum_size */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0xFFFF, /* sealalg */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0, /* authtime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0, /* starttime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) GSS_C_INDEFINITE, /* endtime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) GSS_C_INDEFINITE, /* renew_till */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((int32_t) 0, /* krb_flags */
				   &bp, &remain);
	(void) krb5_ser_pack_int64(seqstate->base, /* seq_send */
				   &bp, &remain);
	(void) krb5_ser_pack_int64(seqstate->base, /* seq_recv */
				   &bp, &remain);

	/* Now dynamic data */
	if (!ret)
	    ret = rfc4121_oid_externalize(mech_used, &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!ret)
	    ret = krb5_externalize_opaque(kcontext, KV5M_PRINCIPAL,
					  dummy_principal, &bp, &remain);
	if (!ret)
	    ret = krb5_externalize_opaque(kcontext, KV5M_PRINCIPAL,
					  dummy_principal, &bp, &remain);
#else
	if (!ret)
	    ret = k5_externalize_principal(dummy_principal, &bp, &remain);
	if (!ret)
	    ret = k5_externalize_principal(dummy_principal, &bp, &remain);
#endif
	if (!ret)
	    ret = rfc4121_seqstate_externalize(seqstate, &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!ret)
	    ret = krb5_externalize_opaque(kcontext, KV5M_CONTEXT,
					  kcontext, &bp, &remain);
	if (!ret)
	    ret = krb5_externalize_opaque(kcontext, KV5M_AUTH_CONTEXT,
					  dummy_auth_context, &bp, &remain);
#else
	if (!ret)
	    ret = k5_externalize_context(kcontext, &bp, &remain);

	if (!ret)
	    ret = k5_externalize_auth_context(dummy_auth_context,
					      &bp, &remain);
#endif
	if (!ret)
	    ret = krb5_ser_pack_int32(1, &bp, &remain); /* proto 1 is RFC4121 */
	if (!ret)
	    ret = krb5_ser_pack_int32((int32_t) cksumtype,
				       &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!ret)
	    ret = krb5_externalize_opaque(kcontext, KV5M_KEYBLOCK,
					  acceptor_subkey, &bp, &remain);
#else
	if (!ret)
	    ret = k5_externalize_keyblock(acceptor_subkey,
					  &bp, &remain);
#endif
	if (!ret)
	    ret = krb5_ser_pack_int32((int32_t) cksumtype, /* acceptor subkey cksumtype */
				      &bp, &remain);
	if (!ret)
	    ret = krb5_ser_pack_int32(0, &bp, &remain); /* rcache */
	if (!ret)
	    ret = krb5_ser_pack_int32(0, &bp, &remain); /* auth_data count */
	if (!ret)
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	    ret = krb5_externalize_opaque(kcontext, KV5M_AUTHDATA_CONTEXT,
					  dummy_authdata_context, &bp, &remain);
#else
	    ret = k5_externalize_authdata_context(kcontext, dummy_authdata_context,
						  &bp, &remain);
#endif
	/* trailer */
	if (!ret)
	    ret = krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);
    }

    return ret;
}

#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
extern krb5_error_code krb5_ser_context_init(krb5_context);
extern krb5_error_code krb5_ser_auth_context_init(krb5_context);

static krb5_error_code
mit_serialization_init(krb5_context context)
{
    krb5_error_code code;
    static krb5_error_code (KRB5_CALLCONV *const fns[])(krb5_context) = {
        krb5_ser_context_init, krb5_ser_auth_context_init,
    };
    size_t i;

    for (i = 0; i < sizeof(fns)/sizeof(fns[0]); i++)
        if ((code = (fns[i])(context)) != 0)
            return code;

    return 0;
}
#endif /* HAVE_KRB5_EXTERNALIZE_OPAQUE */

OM_uint32
_gss_mg_import_rfc4121_context(OM_uint32 *minor,
			       int is_initiator,
			       OM_uint32 gss_flags,
			       krb5_enctype etype,
			       gss_const_buffer_t session_key,
			       gss_ctx_id_t *ctx)
{
    OM_uint32 major = GSS_S_FAILURE;
    struct g_seqnum_state_st seqstate;
    krb5_keyblock keyblock;
    krb5_context context;
    krb5_error_code ret;
    unsigned int count;
    krb5_cksumtype *cksumtypes = NULL;
    krb5_principal dummy_principal = NULL;
    krb5_auth_context dummy_auth_context = NULL;
    krb5_authdata_context dummy_authdata_context = NULL;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

    *minor = 0;
    *ctx = GSS_C_NO_CONTEXT;

    if (gss_mg_import_sec_context == NULL)
	return GSS_S_UNAVAILABLE;

    memset(&seqstate, 0, sizeof(seqstate));
    if (gss_flags & GSS_C_REPLAY_FLAG)
	seqstate.do_replay = 1;
    if (gss_flags & GSS_C_SEQUENCE_FLAG)
	seqstate.do_sequence = 1;
    seqstate.seqmask = UINT64_MAX;
    seqstate.base = 0;

    keyblock.magic = KV5M_KEYBLOCK;
    keyblock.enctype = etype;
    keyblock.length = session_key->length;
    keyblock.contents = session_key->value;

    ret = krb5_init_context(&context);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
    if (ret == 0)
	ret = mit_serialization_init(context);
#endif
    if (ret == 0)
	ret = krb5_parse_name(context, SANON_WELLKNOWN_USER_NAME, &dummy_principal);
    if (ret == 0)
	ret = krb5_auth_con_init(context, &dummy_auth_context);
    if (ret == 0)
	ret = krb5_authdata_context_init(context, &dummy_authdata_context);
    if (ret == 0) {
	ret = krb5_c_keyed_checksum_types(context, etype, &count, &cksumtypes);
	if (count < 1)
	    ret = EINVAL;
    }
    if (ret == 0)
	ret = rfc4121_ctx_externalize(context, is_initiator, gss_flags,
				      gss_mech_krb5, dummy_principal,
				      &seqstate, cksumtypes[count - 1],
				      dummy_auth_context, &keyblock,
				      dummy_authdata_context, &token);
    if (ret == 0)
	major = gss_mg_import_sec_context(minor, &token, ctx);

    if (token.value) {
	zap(token.value, token.length);
	free(token.value);
    }
    krb5_free_cksumtypes(context, cksumtypes);
    krb5_authdata_context_free(context, dummy_authdata_context);
    krb5_auth_con_free(context, dummy_auth_context);
    krb5_free_principal(context, dummy_principal);
    krb5_free_context(context);

    if (*minor == 0)
	*minor = ret;

    return major;
}
