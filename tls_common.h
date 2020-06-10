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

/* Initialization of a new SSL_CTX */
SSL_CTX* SSL_CTX_create(global_config* settings);

/* SSL_CTX loading */
long get_tls_version(enum tls_version version);
int load_certificate_authority(SSL_CTX* ctx, char* CA_path);
int load_cipher_list(SSL_CTX* ctx, char** list, int num);
int load_ciphersuites(SSL_CTX* ctx, char** list, int num);


/* setsockopt */
int get_peer_certificate(socket_ctx* conn, char** data, unsigned int* len);
int get_peer_identity(socket_ctx* conn_ctx, char** data, unsigned int* len);
int get_hostname(socket_ctx* conn_ctx, char** data, unsigned int* len);
int get_enabled_ciphers(socket_ctx* conn, char** data, unsigned int* len);

/* setsockopt */
int set_connection_client(socket_ctx* conn, daemon_ctx* daemon);
int set_connection_server(socket_ctx* conn, daemon_ctx* daemon);
int set_trusted_CA_certificates(socket_ctx *sock_ctx, char* path);
int disable_cipher(socket_ctx* sock_ctx, char* cipher);
int set_certificate_chain(socket_ctx* sock_ctx, char* path);
int set_private_key(socket_ctx* sock_ctx, char* path);

int prepare_SSL_connection(socket_ctx* sock_ctx, int is_client);
int prepare_bufferevents(socket_ctx* sock_ctx, int plain_fd);


