#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>

#include "bev_callbacks.h"
#include "config.h"
#include "daemon_structs.h"
#include "log.h"
#include "tls_server.h"







/**
 * Sets up and begins bufferevents for both the inner facing connection and
 * the secure external-facing TLS connection.
 * 
 * @returns 0 on success, or a negative errno error code otherwise. On error,
 * ifd and new_sock->fd will both be closed, and new_sock->fd will be set to
 * -1. ifd cannot be changed, as it is an argument to the function. As well,
 * the SSL object associated with new_sock will be freed.
 */
int accept_connection_setup(socket_ctx* new_sock, socket_ctx* old_sock, 
        evutil_socket_t ifd) {
    daemon_ctx* daemon = old_sock->daemon;
	connection* accept_conn = new_sock->conn;
	struct sockaddr* internal_addr = &old_sock->int_addr;
	int internal_addrlen = old_sock->int_addrlen;
	int ret;

	accept_conn->addr = internal_addr;
	accept_conn->addrlen = internal_addrlen;

	accept_conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base, 
			new_sock->fd, new_sock->conn->ssl, BUFFEREVENT_SSL_ACCEPTING, 0);
	if (accept_conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		goto err;
	}
	
	bufferevent_setcb(accept_conn->secure.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(accept_conn->secure.bev, 1);
	#endif
	
	/* This will still result in a CONNECTED event--TLS also has to connect */
	ret = bufferevent_enable(accept_conn->secure.bev, EV_READ | EV_WRITE);
	if (ret != 0) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Secure bev enable failed [listener]\n");
		goto err;
	}

	/* Should be the last error-prone function to be called, so that on errror
	 * ifd doesn't get closed twice by the calling function */
	accept_conn->plain.bev = bufferevent_socket_new(daemon->ev_base, 
			ifd, BEV_OPT_CLOSE_ON_FREE);
	if (accept_conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Server bev setup failed [listener]\n");
		goto err;
	}

	bufferevent_setcb(accept_conn->plain.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);

    return 0;
err:
	/* closing/freeing is left up to the calling function */
    return ret;
}



/*******************************************************************************
 *                      SETSOCKOPT FUNCTIONS
 ******************************************************************************/


