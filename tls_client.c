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

    connection* conn = sock_ctx->conn;
    char* hostname = sock_ctx->rem_hostname;
    int ret;

	conn->ssl = SSL_new(sock_ctx->ssl_ctx);
	if (conn->ssl == NULL)
		return ssl_malloc_err(sock_ctx->conn);

    if (hostname != NULL) {
		log_printf(LOG_INFO, "Hostname passed in is: %s\n", hostname);
		SSL_set_tlsext_host_name(conn->ssl, hostname);
		ret = SSL_set1_host(conn->ssl, hostname);
		if (ret != 1) {
			set_err_string(conn, "Connection setup error: "
					"couldn't assign hostname associated with the connection");
			ret = -ECONNABORTED; /* TODO: set SSL error here */
			goto err;
		}
	}

	return 0;
 err:
    SSL_free(conn->ssl);
    return ret;
}

/**
 * Prepares a client connection by creating/configuring bufferevents and
 * setting hostname validation.
 *
 * @param sock_ctx The socket context of the connection to be set up.
 * @returns 0 on success; -errno on failure. In the event of a failure, it is
 * left to the calling function to clean up sock_ctx and set its error state.
 */
int client_connection_setup(socket_ctx* sock_ctx) {

	daemon_ctx* daemon = sock_ctx->daemon;
	connection* conn = sock_ctx->conn;
	int ret;

    struct timeval read_timeout = {
			.tv_sec = EXT_CONN_TIMEOUT,
			.tv_usec = 0,
	};

    if (!(sock_ctx->revocation.checks & NO_REVOCATION_CHECKS)) {
        ret = SSL_CTX_set_tlsext_status_type(sock_ctx->ssl_ctx, 
                    TLSEXT_STATUSTYPE_ocsp);
        if (ret != 1)
            goto err;

        ret = SSL_CTX_set_tlsext_status_arg(sock_ctx->ssl_ctx, (void*) sock_ctx);
        if (ret != 1)
            goto err;

        ret = SSL_CTX_set_tlsext_status_cb(sock_ctx->ssl_ctx, revocation_cb);
        if (ret != 1)
            goto err;
    }


    ret = client_SSL_new(sock_ctx);
    if (conn->ssl == NULL) {
        set_err_string(conn, "Connection setup error: "
                "failed to allocate internals for the daemon connection");
        goto err;
    }


	/* socket set to -1 because we set it later */
	conn->plain.bev = bufferevent_socket_new(daemon->ev_base,
			NOT_CONN_BEV, BEV_OPT_CLOSE_ON_FREE);
	if (conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Connection setup error: "
				"failed to allocate buffers within the SSA daemon");
		goto err;
	}

	conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base,
			sock_ctx->fd, conn->ssl, BUFFEREVENT_SSL_CONNECTING, 0);
	if (conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Connection setup error: "
				"failed to allocate buffers within the SSA daemon");
		goto err;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL */
	bufferevent_openssl_set_allow_dirty_shutdown(conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(conn->secure.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);
	bufferevent_setcb(conn->plain.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);


	ret = bufferevent_set_timeouts(conn->secure.bev, &read_timeout, NULL);
	if (ret < 0) {
		ret = -ECONNABORTED;
		set_err_string(conn, "Connection setup error: "
				"failed to set timeouts within the daemon");
		goto err;
	}

	ret = bufferevent_enable(conn->secure.bev, EV_READ | EV_WRITE);
	if (ret < 0) {
		ret = -ECONNABORTED;
		set_err_string(conn, "Connection setup error: "
				"enabling read/write for connections within the daemon failed");
		goto err;
	}

	return 0;
 err:
	log_printf(LOG_ERROR, "Failed to set up client/server bev [direct mode]\n");
	/* NOTE: intentionally left to the calling function to clean up errors */
	return ret;
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