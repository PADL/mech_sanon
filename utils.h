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

#ifndef UTILS_H
#define UTILS_H 1

static inline void
zero_data(krb5_data *data)
{
    data->magic = KV5M_DATA;
    data->data = NULL;
    data->length = 0;
}

static inline krb5_error_code
alloc_data(krb5_data *data, size_t len)
{
    char *ptr;

    ptr = malloc(len);
    if (ptr == NULL)
	return ENOMEM;

    data->magic = KV5M_DATA;
    data->data = ptr;
    data->length = len;

    return 0;
}

static inline krb5_data
make_data(uint8_t *ptr, size_t len)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = (char *)ptr;
    d.length = len;

    return d;
}

static inline int
buffer_equal_p(gss_const_buffer_t b1, gss_const_buffer_t b2)
{
    return b1->length == b2->length &&
	memcmp(b1->value, b2->value, b2->length) == 0;
}

static inline OM_uint32
alloc_buffer(OM_uint32 *minor, gss_buffer_t buffer, size_t len)
{
    buffer->value = malloc(len);
    if (buffer->value == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    buffer->length = len;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static inline OM_uint32
copy_buffer(OM_uint32 *minor, gss_const_buffer_t src, gss_buffer_t dst)
{
    OM_uint32 major;

    major = alloc_buffer(minor, dst, src->length);
    if (major != GSS_S_COMPLETE)
	return major;

    memcpy(dst->value, src->value, src->length);

    *minor = 0;
    return GSS_S_COMPLETE;
}

static inline void
encode_be_uint32(uint32_t n, uint8_t *p)
{
    p[0] = (n >> 24) & 0xFF;
    p[1] = (n >> 16) & 0xFF;
    p[2] = (n >> 8 ) & 0xFF;
    p[3] = (n >> 0 ) & 0xFF;
}

static inline void
decode_be_uint32(const void *ptr, uint32_t *n)
{
    const uint8_t *p = ptr;
    *n = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3] << 0);
}

static inline void
encode_le_uint32(uint32_t n, uint8_t *p)
{
    p[0] = (n >> 0 ) & 0xFF;
    p[1] = (n >> 8 ) & 0xFF;
    p[2] = (n >> 16) & 0xFF;
    p[3] = (n >> 24) & 0xFF;
}

static inline void
decode_le_uint32(const void *ptr, uint32_t *n)
{
    const uint8_t *p = ptr;
    *n = (p[0] << 0) | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline void
zap(void *s, size_t n)
{
#ifdef HAVE_MEMSET_S
    if (n)
	memset_s(s, n, 0, n);
#else
    if (n)
	memset(s, 0, n);
    __asm__ __volatile__("" : : "g" (s) : "memory");
#endif
}

static inline void
zap_release_buffer(gss_buffer_t buffer)
{
    OM_uint32 tmp;

    if (buffer != GSS_C_NO_BUFFER && buffer->value)
	zap(buffer->value, buffer->length);
    gss_release_buffer(&tmp, buffer);
}

#endif /* UTILS_H */
