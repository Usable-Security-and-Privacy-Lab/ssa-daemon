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

#include <event2/util.h>
#include "daemon_structs.h"



/* SSL_CTX loading */
long get_tls_version(enum tls_version_t version);
int load_certificate_authority(SSL_CTX* ctx, char* CA_path);
int load_cipher_list(SSL_CTX* ctx, char** list, int num);
int load_ciphersuites(SSL_CTX* ctx, char** list, int num);


/* setsockopt */
int get_peer_certificate(connection* conn, char** data, unsigned int* len);
int get_peer_identity(connection* conn_ctx, char** data, unsigned int* len);
int get_hostname(connection* conn_ctx, char** data, unsigned int* len);
int get_enabled_ciphers(connection* conn, char** data, unsigned int* len);

/* setsockopt */
int set_connection_client(connection* conn, daemon_context* daemon);
int set_connection_server(connection* conn, daemon_context* daemon);
int set_trusted_CA_certificates(connection* conn, char* path);
int disable_cipher(connection* conn, char* cipher);
int set_certificate_chain(connection* conn, char* path);
int set_private_key(connection* conn, char* path);


