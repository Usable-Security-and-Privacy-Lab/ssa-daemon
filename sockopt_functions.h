#ifndef SSA_SOCKOPT_FUNCTIONS_H
#define SSA_SOCKOPT_FUNCTIONS_H

#include "daemon_structs.h"

/*helper*/
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);

/* setsockopt */
int get_peer_certificate(socket_ctx* sock_ctx,
            const char** data, unsigned int* len);
int get_peer_identity(socket_ctx* sock_ctx,
            const char** data, unsigned int* len);
int get_hostname(socket_ctx* sock_ctx,
            const char** data, unsigned int* len);
int get_enabled_ciphers(socket_ctx* sock_ctx,
             const char** data, unsigned int* len);
const char* get_chosen_cipher(socket_ctx* sock_ctx, unsigned int* len);

/*
int get_tls_context(socket_ctx* sock_ctx, const char** data, int* len);
*/

/* setsockopt */
int set_connection_client(socket_ctx* conn, daemon_ctx* daemon);
int set_connection_server(socket_ctx* conn, daemon_ctx* daemon);
int set_trusted_CA_certificates(socket_ctx *sock_ctx, char* path);
int disable_cipher(socket_ctx* sock_ctx, char* cipher);
int set_certificate_chain(socket_ctx* sock_ctx, char* path);
int set_private_key(socket_ctx* sock_ctx, char* path);
void set_no_compression(socket_ctx* sock_ctx);

/*
int set_tls_context(socket_ctx* sock_ctx, char *data, long len);
*/

int set_remote_hostname(socket_ctx* sock_ctx, char* hostname, long len);


#endif
