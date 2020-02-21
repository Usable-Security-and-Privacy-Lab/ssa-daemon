#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "tls_common.h"
#include "daemon.h"


SSL_CTX* server_settings_init(char* path);

connection* server_connection_new(daemon_context* daemon);
int server_connection_setup(connection* client_conn, daemon_context* daemon_ctx, char* hostname, evutil_socket_t efd, int is_accepting);























#endif