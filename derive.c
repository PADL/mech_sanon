/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "sanon_locl.h"

extern krb5_error_code
krb5int_hmac(const struct krb5_hash_provider *hash,
	     krb5_key key, const krb5_crypto_iov *data,
	     size_t num_data, krb5_data *output);

/*
 * NIST SP800-108 KDF in counter mode (section 5.1).
 * Parameters:
 *   - HMAC (with hash as the hash provider) is the PRF.
 *   - A block counter of four bytes is used.
 *   - Four bytes are used to encode the output length in the PRF input.
 *
 * There are no uses requiring more than a single PRF invocation.
 */
krb5_error_code
SP800_108_HMAC(const struct krb5_hash_provider *hash,
	       krb5_key inkey, krb5_data *outrnd,
	       const krb5_data *label, const krb5_data *context)
{
    krb5_crypto_iov iov[5];
    krb5_error_code ret;
    krb5_data prf;
    unsigned char ibuf[4], lbuf[4];

    if (hash == NULL || outrnd->length > hash->hashsize)
        return KRB5_CRYPTO_INTERNAL;

    /* Allocate encryption data buffer. */
    ret = alloc_data(&prf, hash->hashsize);
    if (ret)
        return ret;

    /* [i]2: four-byte big-endian binary string giving the block counter (1) */
    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = make_data(ibuf, sizeof(ibuf));
    encode_be_uint32(1, ibuf);
    /* Label */
    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data = *label;
    /* 0x00: separator byte */
    iov[2].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[2].data = make_data((uint8_t *)"", 1);
    /* Context */
    iov[3].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[3].data = *context;
    /* [L]2: four-byte big-endian binary string giving the output length */
    iov[4].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[4].data = make_data(lbuf, sizeof(lbuf));
    encode_be_uint32(outrnd->length * 8, lbuf);

    ret = krb5int_hmac(hash, inkey, iov, 5, &prf);
    if (ret == 0)
        memcpy(outrnd->data, prf.data, outrnd->length);

    secure_zero_memory(prf.data, prf.length);
    free(prf.data);

    return ret;
}
