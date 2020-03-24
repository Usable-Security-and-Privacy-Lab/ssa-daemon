#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "tls_server.h"
#include "tls_structs.h"
#include "log.h"

SSL_CTX* server_settings_init(char* path) {
    return NULL; /* TODO: stub */
}

int server_SSL_new(connection* conn, daemon_context* daemon) {
	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = SSL_new(daemon->server_settings);
	if (conn->tls == NULL) {
		/* TODO: determine if the error was actually an out-of-memory issue */
		return -ENOMEM;
	}
	return 0;
}

int accept_ssl_new(SSL** ssl, connection* old) {
	int ret = 0;

	if (*ssl != NULL) 
		SSL_free(*ssl);
	*ssl = SSL_dup(old->tls);
	if (*ssl == NULL) {
		/* TODO: get openssl error and return here */
		ret = -ENOMEM;
	}
	return ret;
}

int accept_connection_setup(sock_context* new_sock, sock_context* old_sock, 
        evutil_socket_t ifd) {
    daemon_context* daemon = new_sock->daemon;
	connection* accept_conn = new_sock->tls_conn;
	struct sockaddr* internal_addr = &old_sock->int_addr;
	int internal_addrlen = old_sock->int_addrlen;
	evutil_socket_t efd = new_sock->fd;
	int ret = 0;

	accept_conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base, 
			efd, accept_conn->tls, BUFFEREVENT_SSL_ACCEPTING, 
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (accept_conn->secure.bev == NULL) {
		ret = EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(efd);
		connection_free(accept_conn);
		goto err;
	}
	accept_conn->secure.connected = 1;

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(accept_conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	accept_conn->plain.bev = bufferevent_socket_new(daemon->ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (accept_conn->plain.bev == NULL) {
		ret = EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(ifd);
		connection_free(accept_conn);
		goto err;
	}

	accept_conn->addr = internal_addr;
	accept_conn->addrlen = internal_addrlen;
	
	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(accept_conn->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, accept_conn);
	//bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(accept_conn->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, accept_conn);
	bufferevent_enable(accept_conn->secure.bev, EV_READ | EV_WRITE);

    return ret;
err:
    /* Do stuff here... */
    return ret;
}



/*
 **********************************
 * Function from setsockopt()
 **********************************
 */
int set_remote_hostname(connection* conn_ctx, char* hostname) {
	if (conn_ctx == NULL) {
		/* We don't fail here because this will be set when the
		 * connection is actually created by tls_client_setup */
		return 1;
	}
	SSL_set_tlsext_host_name(conn_ctx->tls, hostname);
	return 1;
}