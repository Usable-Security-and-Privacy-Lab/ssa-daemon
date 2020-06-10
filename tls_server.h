#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "tls_common.h"
#include "daemon_structs.h"


int accept_connection_setup(socket_ctx* new_sock, socket_ctx* old_sock, 
        evutil_socket_t ifd);















#endif