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
rfc4121_oid_externalize(gss_OID oid, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code err;

    err = krb5_ser_pack_int32(KV5M_GSS_OID, buffer, lenremain);
    if (err)
	return err;
    err = krb5_ser_pack_int32((krb5_int32) oid->length,
			      buffer, lenremain);
    if (err)
	return err;
    err = krb5_ser_pack_bytes((krb5_octet *) oid->elements,
			      oid->length, buffer, lenremain);
    if (err)
	return err;
    err = krb5_ser_pack_int32(KV5M_GSS_OID, buffer, lenremain);
    return err;
}

static krb5_error_code
rfc4121_oid_size(gss_OID oid, size_t *sizep)
{
    krb5_error_code kret;
    size_t required;

    kret = EINVAL;
    if (oid != NULL) {
	required = 2*sizeof(krb5_int32); /* For the header and trailer */
	required += sizeof(krb5_int32);
	required += oid->length;

	kret = 0;

	*sizep += required;
    }

    return(kret);
}

static void
g_seqstate_size(g_seqnum_state state, size_t *sizep)
{
    *sizep += sizeof(*state);
}

static krb5_error_code
g_seqstate_externalize(g_seqnum_state state, unsigned char **buf,
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
			   krb5_octet **buffer,
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
    krb5_error_code kret;
    size_t required;

    kret = EINVAL;
    if (arg) {
	required = 2*sizeof(krb5_int32); /* For the header and trailer */
	g_seqstate_size(arg, &required);

	kret = 0;
	*sizep += required;
    }
    return(kret);
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
    krb5_error_code     kret;
    size_t	      required;

    /*
     * krb5_gss_ctx_id_rec requires:
     *  krb5_int32      for KG_CONTEXT
     *  krb5_int32      for initiate.
     *  krb5_int32      for established.
     *  krb5_int32      for have_acceptor_subkey.
     *  krb5_int32      for seed_init.
     *  krb5_int32      for gss_flags.
     *  sizeof(seed)    for seed
     *  ...	     for here
     *  ...	     for there
     *  ...	     for subkey
     *  krb5_int32      for signalg.
     *  krb5_int32      for cksum_size.
     *  krb5_int32      for sealalg.
     *  ...	     for enc
     *  ...	     for seq
     *  krb5_int32      for authtime.
     *  krb5_int32      for starttime.
     *  krb5_int32      for endtime.
     *  krb5_int32      for renew_till.
     *  krb5_int32      for flags.
     *  int64_t	 for seq_send.
     *  int64_t	 for seq_recv.
     *  ...	     for seqstate
     *  ...	     for auth_context
     *  ...	     for mech_used
     *  krb5_int32      for proto
     *  krb5_int32      for cksumtype
     *  ...	     for acceptor_subkey
     *  krb5_int32      for acceptor_key_cksumtype
     *  krb5_int32      for cred_rcache
     *  krb5_int32      for number of elements in authdata array
     *  ...	     for authdata array
     *  krb5_int32      for trailer.
     */
    kret = EINVAL;
    required = 4 + mech_used->length;
    required += 21*sizeof(krb5_int32);
    required += 2*sizeof(int64_t);
    required += sizeof(seed);

    kret = 0;

    if (!kret)
	kret = rfc4121_oid_size(mech_used, &required);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_PRINCIPAL,
				dummy_principal, &required);
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_PRINCIPAL,
				dummy_principal, &required);
#else
    if (!kret)
	kret = k5_size_principal(dummy_principal, &required);
    if (!kret)
	kret = k5_size_principal(dummy_principal, &required);
#endif
    if (!kret)
	kret = rfc4121_seqstate_size(seqstate, &required);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_CONTEXT,
				kcontext, &required);
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_AUTH_CONTEXT,
				dummy_auth_context, &required);
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_KEYBLOCK,
				acceptor_subkey, &required);
    if (!kret)
	kret = krb5_size_opaque(kcontext, KV5M_AUTHDATA_CONTEXT,
				dummy_authdata_context, &required);
#else
    if (!kret)
	kret = k5_size_context(kcontext, &required);
    if (!kret)
	kret = k5_size_auth_context(dummy_auth_context, &required);
    if (!kret)
	kret = k5_size_keyblock(acceptor_subkey, &required);
    if (!kret)
	kret = k5_size_authdata_context(kcontext, dummy_authdata_context, &required);
#endif
    *sizep += required;

    return(kret);
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
		   krb5_octet **buffer,
		   size_t *lenremain)

{
    krb5_error_code     kret;
    size_t	      required;
    krb5_octet	  *bp;
    size_t	      remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = ENOMEM;
    if (!rfc4121_ctx_size(kcontext, mech_used, dummy_principal, seqstate,
			  dummy_auth_context, acceptor_subkey,
			  dummy_authdata_context, &required) &&
	(required <= remain)) {
	/* GSS token framing */
	kret = krb5_ser_pack_int32(mech_used->length, &bp, &remain);
	if (!kret)
	    kret = krb5_ser_pack_bytes(mech_used->elements, mech_used->length,
				       &bp, &remain);

	/* Our identifier */
	(void) krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);

	/* Now static data */
	(void) krb5_ser_pack_int32((krb5_int32) is_initiator,
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 1, /* established */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 1, /* have_acceptor_subkey */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0, /* seed_init */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) gss_flags,
				   &bp, &remain);
	(void) krb5_ser_pack_bytes(seed, sizeof(seed),
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0xFFFF, /* signalg */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0, /* cksum_size */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0xFFFF, /* sealalg */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0, /* authtime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0, /* starttime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) GSS_C_INDEFINITE, /* endtime */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) GSS_C_INDEFINITE, /* renew_till */
				   &bp, &remain);
	(void) krb5_ser_pack_int32((krb5_int32) 0, /* krb_flags */
				   &bp, &remain);
	(void) krb5_ser_pack_int64(seqstate->base, /* seq_send */
				   &bp, &remain);
	(void) krb5_ser_pack_int64(seqstate->base, /* seq_recv */
				   &bp, &remain);

	/* Now dynamic data */
	if (!kret)
	    kret = rfc4121_oid_externalize(mech_used, &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!kret)
	    kret = krb5_externalize_opaque(kcontext, KV5M_PRINCIPAL,
					   dummy_principal, &bp, &remain);
	if (!kret)
	    kret = krb5_externalize_opaque(kcontext, KV5M_PRINCIPAL,
					   dummy_principal, &bp, &remain);
#else
	if (!kret)
	    kret = k5_externalize_principal(dummy_principal, &bp, &remain);
	if (!kret)
	    kret = k5_externalize_principal(dummy_principal, &bp, &remain);
#endif
	if (!kret)
	    kret = rfc4121_seqstate_externalize(seqstate, &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!kret)
	    kret = krb5_externalize_opaque(kcontext, KV5M_CONTEXT,
					   kcontext, &bp, &remain);
	if (!kret)
	    kret = krb5_externalize_opaque(kcontext, KV5M_AUTH_CONTEXT,
					   dummy_auth_context, &bp, &remain);
#else
	if (!kret)
	    kret = k5_externalize_context(kcontext, &bp, &remain);

	if (!kret)
	    kret = k5_externalize_auth_context(dummy_auth_context,
					       &bp, &remain);
#endif
	if (!kret)
	    kret = krb5_ser_pack_int32(1, &bp, &remain); /* proto 1 is RFC4121 */
	if (!kret)
	    kret = krb5_ser_pack_int32((krb5_int32) cksumtype,
				       &bp, &remain);
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	if (!kret)
	    kret = krb5_externalize_opaque(kcontext, KV5M_KEYBLOCK,
					   acceptor_subkey, &bp, &remain);
#else
	if (!kret)
	    kret = k5_externalize_keyblock(acceptor_subkey,
					   &bp, &remain);
#endif
	if (!kret)
	    kret = krb5_ser_pack_int32((krb5_int32) cksumtype, /* acceptor subkey cksumtype */
				       &bp, &remain);
	if (!kret)
	    kret = krb5_ser_pack_int32(0, &bp, &remain); /* rcache */
	if (!kret)
	    kret = krb5_ser_pack_int32(0, &bp, &remain); /* auth_data count */
	if (!kret)
#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
	    kret = krb5_externalize_opaque(kcontext, KV5M_AUTHDATA_CONTEXT,
					   dummy_authdata_context, &bp, &remain);
#else
	    kret = k5_externalize_authdata_context(kcontext, dummy_authdata_context,
						   &bp, &remain);
#endif
	/* trailer */
	if (!kret)
	    kret = krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);
	if (!kret) {
	    *buffer = bp;
	    *lenremain = remain;
	}
    }

    return kret;
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
    unsigned int i;

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
    size_t size = 0, lenremain;
    unsigned int count;
    krb5_octet *buffer = NULL, *bufp;
    krb5_cksumtype *cksumtypes = NULL;
    krb5_principal dummy_principal = NULL;
    krb5_auth_context dummy_auth_context = NULL;
    krb5_authdata_context dummy_authdata_context = NULL;

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
    if (ret == 0)
	ret = rfc4121_ctx_size(context, gss_mech_krb5, dummy_principal,
			       &seqstate, dummy_auth_context, &keyblock,
			       dummy_authdata_context, &size);
    if (ret == 0) {
	bufp = buffer = calloc(1, size);
	if (buffer == NULL)
	    ret = ENOMEM;

	lenremain = size;
    }
    if (ret == 0) {
	ret = krb5_c_keyed_checksum_types(context, etype, &count, &cksumtypes);
	if (count < 1)
	    ret = EINVAL;
    }
    if (ret == 0) {
	ret = rfc4121_ctx_externalize(context, is_initiator, gss_flags,
				      gss_mech_krb5, dummy_principal,
				      &seqstate, cksumtypes[count - 1],
				      dummy_auth_context, &keyblock,
				      dummy_authdata_context, &bufp, &lenremain);
    }
    if (ret == 0) {
	gss_buffer_desc token;

	token.length = size - lenremain;
	token.value = buffer;

	major = gss_mg_import_sec_context(minor, &token, ctx);
    }

    if (buffer) {
	zap(buffer, size);
	free(buffer);
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
