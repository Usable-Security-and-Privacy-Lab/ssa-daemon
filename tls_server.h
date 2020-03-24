#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "tls_common.h"
#include "tls_structs.h"

SSL_CTX* server_settings_init(char* path);

int server_SSL_new(connection* conn, daemon_context* daemon);
int accept_SSL_new(connection* conn, connection* old);

int accept_connection_setup(sock_context* new_sock, sock_context* old_sock, 
        evutil_socket_t ifd);

int set_remote_hostname(connection* conn_ctx, char* hostname);















#endif