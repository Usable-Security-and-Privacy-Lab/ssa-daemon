/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "in_tls.h"


#define MAX_CHAIN_DEPTH 256


int read_ca_path(file_stream *fs, global_config *conf);
int read_chain_depth(file_stream *fs, global_config *conf);
int read_ct_checks(file_stream *fs, global_config *conf);
int read_cipherlist(file_stream *fs, global_config *conf);
int read_ciphersuites(file_stream *fs, global_config *conf);
int read_max_tls_version(file_stream *fs, global_config *conf);
int read_min_tls_version(file_stream *fs, global_config *conf);
int read_revocation_cached(file_stream *fs, global_config *conf);
int read_revocation_checks(file_stream *fs, global_config *conf);
int read_revocation_crl(file_stream *fs, global_config *conf);
int read_revocation_ocsp(file_stream *fs, global_config *conf);
int read_revocation_stapled(file_stream *fs, global_config *conf);
int read_session_resumption(file_stream *fs, global_config *conf);
int read_session_tickets(file_stream *fs, global_config *conf);
int read_session_timeout(file_stream *fs, global_config *conf);


/* labels MUST (!!) stay sorted alphabetically */
/* dashes ('-') come alphabetically before anything else */
const label_pair parser_keys[PARSER_KEY_CNT] = {
    { .label = "cert-transparency-checks", .func = read_ct_checks },
    { .label = "cert-verification-depth", .func = read_chain_depth },
    { .label = "max-tls-version", .func = read_max_tls_version },
    { .label = "min-tls-version", .func = read_min_tls_version },
    { .label = "revocation-cached", .func = read_revocation_cached },
    { .label = "revocation-checks", .func = read_revocation_checks },
    { .label = "revocation-crl", .func = read_revocation_crl },
    { .label = "revocation-ocsp", .func = read_revocation_ocsp },
    { .label = "revocation-stapled", .func = read_revocation_stapled },
    { .label = "session-resumption", .func = read_session_resumption },
    { .label = "session-tickets", .func = read_session_tickets },
    { .label = "session-timeout", .func = read_session_timeout },
    { .label = "tlsv1.2-ciphers", .func = read_cipherlist },
    { .label = "tlsv1.3-ciphers", .func = read_ciphersuites },
    { .label = "trust-store-location", .func = read_ca_path },
};


/* Functions for parsing associated labels--ADD HERE */

int read_ca_path(file_stream *fs, global_config *conf)
{
    if (conf->ca_path != NULL)
        free(conf->ca_path);

    return parser_read_string(fs, &conf->ca_path);
}


int read_chain_depth(file_stream *fs, global_config *conf)
{
    return parser_read_int(fs, &conf->max_chain_depth, 0, MAX_CHAIN_DEPTH);
}


int read_cipherlist(file_stream *fs, global_config *conf)
{
    if (conf->cipher_list != NULL) {
        for (int i = 0; i < conf->cipher_list_cnt; i++)
            free(conf->cipher_list[i]);
        free(conf->cipher_list);
        conf->cipher_list = NULL;
    }

    conf->cipher_list_cnt = parser_read_list(fs, &conf->cipher_list);
    return conf->cipher_list_cnt < 0 ? -1 : 0;
}


int read_ciphersuites(file_stream *fs, global_config *conf)
{
     if (conf->ciphersuites != NULL) {
        for (int i = 0; i < conf->ciphersuite_cnt; i++)
            free(conf->ciphersuites[i]);
        free(conf->ciphersuites);
        conf->ciphersuites = NULL; 
    }

    conf->ciphersuite_cnt = parser_read_list(fs, &conf->ciphersuites);
    return conf->ciphersuite_cnt < 0 ? -1 : 0;
}


int read_ct_checks(file_stream *fs, global_config *conf)
{
    return parser_read_boolean(fs, &conf->ct_checks);
}


int read_max_tls_version(file_stream *fs, global_config *conf)
{
    return parser_read_int(fs, &conf->max_tls_version, TLS_1_0, TLS_1_3);
}


int read_min_tls_version(file_stream *fs, global_config *conf)
{
    return parser_read_int(fs, &conf->min_tls_version, TLS_1_0, TLS_1_3);
}


int read_revocation_cached(file_stream *fs, global_config *conf)
{
    int enabled = 1;
    int err = parser_read_boolean(fs, &enabled);

    if (enabled)
        turn_on_cached_checks(conf->revocation_checks);
    else
        turn_off_cached_checks(conf->revocation_checks);

    return err;
}


int read_revocation_checks(file_stream *fs, global_config *conf)
{
    int enabled = 1;
    int err = parser_read_boolean(fs, &enabled);

    if (enabled)
        turn_on_revocation_checks(conf->revocation_checks);
    else
        turn_off_revocation_checks(conf->revocation_checks);
    
    return err;
}


int read_revocation_crl(file_stream *fs, global_config *conf)
{
    int enabled = 1;
    int err = parser_read_boolean(fs, &enabled);

    if (enabled)
        turn_on_crl_checks(conf->revocation_checks);
    else
        turn_off_crl_checks(conf->revocation_checks);

    return err;
}


int read_revocation_ocsp(file_stream *fs, global_config *conf)
{
    int enabled = 1;
    int err = parser_read_boolean(fs, &enabled);

    if (enabled)
        turn_on_ocsp_checks(conf->revocation_checks);
    else
        turn_off_ocsp_checks(conf->revocation_checks);

    return err;
}


int read_revocation_stapled(file_stream *fs, global_config *conf)
{
    int enabled = 1;
    int err = parser_read_boolean(fs, &enabled);

    if (enabled)
        turn_on_stapled_checks(conf->revocation_checks);
    else
        turn_off_stapled_checks(conf->revocation_checks);

    return err;
}


int read_session_resumption(file_stream *fs, global_config *conf)
{
    return parser_read_boolean(fs, &conf->session_resumption);
}


int read_session_tickets(file_stream *fs, global_config *conf)
{
    return parser_read_boolean(fs, &conf->session_tickets);
}


int read_session_timeout(file_stream *fs, global_config *conf)
{
    return parser_read_int(fs, &conf->session_timeout, 0, INT_MAX);
}

