#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "tls_server.h"
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

connection* server_connection_new(daemon_context* daemon) {
    connection* server_conn = (connection*)calloc(1, sizeof(connection));
    if (server_conn == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate server connection: %s\n", strerror(errno));
		goto err;
	}

    server_conn->tls = SSL_new(daemon->server_settings);
	if (server_conn->tls == NULL) {
        goto err;
	}

    return server_conn;
err:
    /* TODO: connection_free() here */
    return NULL;
}

int server_connection_setup(connection* server_conn, daemon_context* daemon_ctx, 
        evutil_socket_t efd, evutil_socket_t ifd, struct sockaddr* internal_addr, int internal_addrlen) {

	server_conn->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, server_conn->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (server_conn->secure.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(efd);
		connection_free(server_conn);
		goto err;
	}
	server_conn->secure.connected = 1;

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(server_conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	server_conn->plain.bev = bufferevent_socket_new(daemon_ctx->ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (server_conn->plain.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(ifd);
		connection_free(server_conn);
		goto err;
	}

	server_conn->addr = internal_addr;
	server_conn->addrlen = internal_addrlen;
	
	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(server_conn->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, server_conn);
	//bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(server_conn->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, server_conn);
	bufferevent_enable(server_conn->secure.bev, EV_READ | EV_WRITE);

    return 1;
err:
    /* Do stuff here... */
    return 0;
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