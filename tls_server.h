#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "tls_common.h"
#include "daemon.h"


SSL_CTX* server_settings_init(char* path);

connection* server_connection_new(daemon_context* daemon);
int server_connection_setup(connection* server_conn, daemon_context* daemon_ctx, evutil_socket_t efd, 
        evutil_socket_t ifd, struct sockaddr* internal_addr, int internal_addrlen);

int set_remote_hostname(connection* conn_ctx, char* hostname);















#endif