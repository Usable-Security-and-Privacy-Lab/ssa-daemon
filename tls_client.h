/*
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

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <openssl/ocsp.h>

#include "config.h"
#include "daemon_structs.h"



#define EXT_CONN_TIMEOUT 15 /* seconds */

#define MAX_HEADER_SIZE 8192

#define MAX_OCSP_RESPONDERS 5
#define OCSP_READ_TIMEOUT 8

#define LEEWAY_90_SECS 90
#define MAX_OCSP_AGE 604800L /* 7 days is pretty standard for OCSP */

SSL_CTX* client_ctx_init(client_settings* config);

int client_SSL_new(connection* conn, daemon_context* daemon);
int client_connection_setup(sock_context* sock_ctx);

int begin_responder_revocation_checks(sock_context* sock_ctx);
int check_stapled_response(SSL* tls);

char** retrieve_ocsp_urls(X509* cert, int* num_urls);
char** retrieve_crl_urls(X509* cert, int* num_urls);

int parse_url(char* url, char** host_out, int* port_out, char** path_out);

int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp);
int check_ocsp_response(OCSP_BASICRESP* response, SSL* tls);
int check_crl_response(X509_CRL* response, SSL* tls);
OCSP_CERTID* get_ocsp_certid(SSL* tls);

#endif
