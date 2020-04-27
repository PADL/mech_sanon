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

#ifndef MIT_SERIALIZATION_H
#define MIT_SERIALIZATION_H 1

#include "config.h"

typedef struct g_seqnum_state_st {
    /* Flags to indicate whether we are supposed to check for replays or
     * enforce strict sequencing. */
    int do_replay;
    int do_sequence;

    /* UINT32_MAX for 32-bit sequence numbers, UINT64_MAX for 64-bit.  Mask
     * against this after arithmetic to stay within the correct range. */
    uint64_t seqmask;

    /* The initial sequence number for this context.  This value will be
     * subtracted from all received sequence numbers to simplify wraparound. */
    uint64_t base;

    /* The expected next sequence number (one more than the highest previously
     * seen sequence number), relative to base. */
    uint64_t next;

    /*
     * A bitmap for the 64 sequence numbers prior to next.  If the 1<<(i-1) bit
     * is set, then we have seen seqnum next-i relative to base.  The least
     * significant bit is always set if we have received any sequence numbers,
     * and indicates the highest sequence number we have seen (next-1).  When
     * we advance next, we shift recvmap to the left.
     */
    uint64_t recvmap;
} *g_seqnum_state;

extern krb5_error_code KRB5_CALLCONV
krb5_ser_pack_int32(krb5_int32, krb5_octet **, size_t *);

extern krb5_error_code KRB5_CALLCONV
krb5_ser_pack_int64(int64_t, krb5_octet **, size_t *);

extern krb5_error_code KRB5_CALLCONV
krb5_ser_pack_bytes(krb5_octet *, size_t, krb5_octet **, size_t *);

typedef struct _krb5_authdata_context *krb5_authdata_context;

extern krb5_error_code
krb5_authdata_context_init(krb5_context kcontext,
                           krb5_authdata_context *pcontext);

extern void
krb5_authdata_context_free(krb5_context kcontext,
                           krb5_authdata_context context);

#ifdef HAVE_KRB5_EXTERNALIZE_OPAQUE
extern krb5_error_code
krb5_size_opaque(krb5_context kcontext, krb5_magic odtype,
		 krb5_pointer arg, size_t *sizep);

extern krb5_error_code
krb5_externalize_opaque(krb5_context kcontext, krb5_magic odtype,
			krb5_pointer arg, krb5_octet **bufpp, size_t *sizep);
#else
extern krb5_error_code
k5_size_context(krb5_context context, size_t *sizep);

extern krb5_error_code
k5_externalize_context(krb5_context context,
		       krb5_octet **buffer, size_t *lenremain);

extern krb5_error_code
k5_size_keyblock(krb5_keyblock *keyblock, size_t *sizep);

extern krb5_error_code
k5_externalize_keyblock(krb5_keyblock *keyblock,
			krb5_octet **buffer, size_t *lenremain);

extern krb5_error_code
k5_size_principal(krb5_principal principal, size_t *sizep);

extern krb5_error_code
k5_externalize_principal(krb5_principal principal,
			 krb5_octet **buffer, size_t *lenremain);

extern krb5_error_code
k5_size_auth_context(krb5_auth_context auth_context, size_t *sizep);

extern krb5_error_code
k5_externalize_auth_context(krb5_auth_context auth_context,
			    krb5_octet **buffer, size_t *lenremain);

extern krb5_error_code
k5_size_authdata_context(krb5_context kcontext, krb5_authdata_context context,
                         size_t *sizep);

extern krb5_error_code
k5_externalize_authdata_context(krb5_context kcontext,
                                krb5_authdata_context context,
                                krb5_octet **buffer, size_t *lenremain);
#endif /* HAVE_KRB5_EXTERNALIZE_OPAQUE */

#endif
