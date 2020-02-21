#include "tls_server.h"


SSL_CTX* server_settings_init(char* path) {
    return NULL; /* TODO: stub */
}

connection* server_connection_new(daemon_context* daemon) {


}

int server_connection_setup(connection* client_conn, daemon_context* daemon_ctx, char* hostname, evutil_socket_t efd, int is_accepting) {


}
