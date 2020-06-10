#include <errno.h>
#include <string.h>

#include <unistd.h> //added to use the `access()` function call.


#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "bev_callbacks.h"
#include "config.h"
#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "daemon_structs.h"




/**
 * Attempts to create a new SSL struct and attach it to the given connection.
 * If unsuccessful, the connection's state will not be altered--if it
 * contained an SSL struct prior to this call, that struct will remain.
 * @param conn The connection to assign a new client SSL struct to.
 * @returns 0 on success; -errno otherwise.
 */
int client_SSL_new(socket_ctx* sock_ctx) {

	sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
	if (sock_ctx->ssl == NULL)
		return ssl_malloc_err(sock_ctx);

    SSL_set_verify(sock_ctx->ssl, SSL_VERIFY_PEER, NULL);

	return 0;
}


/**
 *
 * 
 */
int set_remote_hostname(socket_ctx* sock_ctx, char* hostname, long len) {

    if (len > MAX_HOSTNAME || len <= 0)
        return -EINVAL;

    memcpy(sock_ctx->rem_hostname, hostname, len);
    

	return 0;
}