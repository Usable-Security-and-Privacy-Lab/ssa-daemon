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
#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "daemon.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
int SSL_use_certificate_chain_file(SSL *ssl, const char *file);
#endif



connection* tls_client_wrapper_setup(evutil_socket_t efd, daemon_context* daemon_ctx,
	char* hostname, int is_accepting, tls_opts_t* tls_opts);
void associate_fd(connection* conn, evutil_socket_t ifd);
connection* tls_server_wrapper_setup(evutil_socket_t efd, evutil_socket_t ifd, daemon_context* daemon_ctx,
	tls_opts_t* tls_opts, struct sockaddr* internal_addr, int internal_addrlen);
void free_tls_conn_ctx(connection* ctx);

int set_netlink_cb_params(connection* conn, daemon_context* daemon_ctx, unsigned long id);
tls_opts_t* tls_opts_create(char* path);
void tls_opts_free(tls_opts_t*);
int tls_opts_server_setup(tls_opts_t* ops);
int tls_opts_client_setup(tls_opts_t* ops);


/* Helper functions to separate daemon from security library */
int set_disbled_cipher(tls_opts_t* tls_opts, connection* conn_ctx, char* cipher);
int set_session_ttl(tls_opts_t* tls_opts, connection* conn_ctx, char* ttl);
int set_remote_hostname(tls_opts_t* tls_opts, connection* conn_ctx, char* hostname);
int send_peer_auth_req(tls_opts_t* tls_opts, connection* conn_ctx, char* value);

int get_remote_hostname(tls_opts_t* tls_opts, connection* conn_ctx, char** data, unsigned int* len);
int get_hostname(tls_opts_t* tls_opts, connection* conn_ctx, char** data, unsigned int* len);
int get_certificate_chain(tls_opts_t* tls_opts, connection* conn_ctx, char** data, unsigned int* len);
long get_session_ttl(tls_opts_t* tls_opts, connection* conn_ctx);
int get_peer_identity(tls_opts_t* tls_opts, connection* conn_ctx, char** data, unsigned int* len);
int get_peer_certificate(tls_opts_t* tls_opts, connection* conn_ctx, char** data, unsigned int* len);

#endif
