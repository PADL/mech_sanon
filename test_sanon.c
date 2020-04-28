/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2010  by the Massachusetts Institute of Technology.
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
 *
 */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <assert.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

static gss_OID_desc mech_sanon = { 10, "\x2b\x06\x01\x04\x01\xa9\x4a\x1a\x01\x6e" };
static gss_OID_set_desc mechset_sanon = { 1, &mech_sanon };

static gss_OID_desc mech_spnego = { 6, "\053\006\001\005\005\002" };
static gss_OID_set_desc mechset_spnego = { 1, &mech_spnego };

static void
display_status(const char *msg, OM_uint32 code, int type)
{
    OM_uint32 min_stat, msg_ctx = 0;
    gss_buffer_desc buf;

    do {
        (void)gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
                                 &msg_ctx, &buf);
        fprintf(stderr, "%s: %.*s\n", msg, (int)buf.length, (char *)buf.value);
        (void)gss_release_buffer(&min_stat, &buf);
    } while (msg_ctx != 0);
}

void
check_gsserr(const char *msg, OM_uint32 major, OM_uint32 minor)
{
    if (GSS_ERROR(major)) {
        display_status(msg, major, GSS_C_GSS_CODE);
        display_status(msg, minor, GSS_C_MECH_CODE);
        exit(1);
    }
}

void
check_k5err(krb5_context context, const char *msg, krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(context, code);
        printf("%s: %s\n", msg, errmsg);
        krb5_free_error_message(context, errmsg);
        exit(1);
    }
}

void
errout(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

gss_name_t
import_name(const char *str)
{
    OM_uint32 major, minor;
    gss_name_t name;
    gss_buffer_desc buf;
    gss_OID nametype = NULL;

    if (*str == 'u')
        nametype = GSS_C_NT_USER_NAME;
    else if (*str == 'p')
        nametype = (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME;
    else if (*str == 'h')
        nametype = GSS_C_NT_HOSTBASED_SERVICE;
    else if (*str == 'a')
        nametype = GSS_C_NT_ANONYMOUS;
    if (nametype == NULL || str[1] != ':')
        errout("names must begin with u: or p: or h:");
    buf.value = (char *)str + 2;
    buf.length = strlen(str) - 2;
    major = gss_import_name(&minor, &buf, nametype, &name);
    check_gsserr("gss_import_name", major, minor);
    return name;
}

void
establish_contexts(gss_OID imech, gss_cred_id_t icred, gss_cred_id_t acred,
                   gss_name_t tname, OM_uint32 flags, gss_ctx_id_t *ictx,
                   gss_ctx_id_t *actx, gss_name_t *src_name, gss_OID *amech,
                   gss_cred_id_t *deleg_cred)
{
    OM_uint32 minor, imaj, amaj;
    gss_buffer_desc itok, atok;

    *ictx = *actx = GSS_C_NO_CONTEXT;
    imaj = amaj = GSS_S_CONTINUE_NEEDED;
    itok.value = atok.value = NULL;
    itok.length = atok.length = 0;
    for (;;) {
        (void)gss_release_buffer(&minor, &itok);
        imaj = gss_init_sec_context(&minor, icred, ictx, tname, imech, flags,
                                    GSS_C_INDEFINITE,
                                    GSS_C_NO_CHANNEL_BINDINGS, &atok, NULL,
                                    &itok, NULL, NULL);
        check_gsserr("gss_init_sec_context", imaj, minor);
        if (amaj == GSS_S_COMPLETE)
            break;

        (void)gss_release_buffer(&minor, &atok);
        amaj = gss_accept_sec_context(&minor, actx, acred, &itok,
                                      GSS_C_NO_CHANNEL_BINDINGS, src_name,
                                      amech, &atok, NULL, NULL, deleg_cred);
        check_gsserr("gss_accept_sec_context", amaj, minor);
        (void)gss_release_buffer(&minor, &itok);
        if (imaj == GSS_S_COMPLETE)
            break;
    }

    if (imaj != GSS_S_COMPLETE || amaj != GSS_S_COMPLETE)
        errout("One side wants to continue after the other is done");

    (void)gss_release_buffer(&minor, &itok);
    (void)gss_release_buffer(&minor, &atok);
}

void
export_import_cred(gss_cred_id_t *cred)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_export_cred(&minor, *cred, &buf);
    check_gsserr("gss_export_cred", major, minor);
    (void)gss_release_cred(&minor, cred);
    major = gss_import_cred(&minor, &buf, cred);
    check_gsserr("gss_import_cred", major, minor);
    (void)gss_release_buffer(&minor, &buf);
}

void
display_canon_name(const char *tag, gss_name_t name, gss_OID mech)
{
    gss_name_t canon;
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_canonicalize_name(&minor, name, mech, &canon);
    check_gsserr("gss_canonicalize_name", major, minor);

    major = gss_display_name(&minor, canon, &buf, NULL);
    check_gsserr("gss_display_name", major, minor);

    printf("%s:\t%.*s\n", tag, (int)buf.length, (char *)buf.value);

    (void)gss_release_name(&minor, &canon);
    (void)gss_release_buffer(&minor, &buf);
}

void
display_oid(const char *tag, gss_OID oid)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    major = gss_oid_to_str(&minor, oid, &buf);
    check_gsserr("gss_oid_to_str", major, minor);
    if (tag != NULL)
        printf("%s:\t", tag);
    printf("%.*s\n", (int)buf.length, (char *)buf.value);
    (void)gss_release_buffer(&minor, &buf);
}

int
main(void)
{
    OM_uint32 minor, major, flags;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t initiator_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_ctx_id_t initiator_context, acceptor_context;
    gss_name_t target_name = import_name("a:"), source_name = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;

    /* Get default initiator cred. */
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_INITIATE,
                             &initiator_cred_handle, NULL, NULL);
    check_gsserr("gss_acquire_cred(initiator)", major, minor);

    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             &mechset_spnego, GSS_C_ACCEPT,
                             &verifier_cred_handle, NULL, NULL);
    check_gsserr("gss_acquire_cred(acceptor)", major, minor);

    major = gss_set_neg_mechs(&minor, verifier_cred_handle, &mechset_sanon);
    check_gsserr("gss_set_neg_mechs(acceptor)", major, minor);

    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    establish_contexts(&mech_spnego, initiator_cred_handle,
                       verifier_cred_handle, target_name, flags,
                       &initiator_context, &acceptor_context, &source_name,
                       &mech, NULL);

    display_canon_name("Source name", source_name, &mech_sanon);
    display_oid("Source mech", mech);

    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_name(&minor, &source_name);
    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_cred(&minor, &initiator_cred_handle);
    (void)gss_release_cred(&minor, &verifier_cred_handle);
    (void)gss_release_oid_set(&minor, &actual_mechs);

    return 0;
}
