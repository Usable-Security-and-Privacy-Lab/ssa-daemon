#include "daemon_structs.h"
#include "log.h"

#include "event2/bufferevent.h"
#include "event2/listener.h"
#include "unistd.h"



int sock_context_new(sock_context** sock_ctx, 
		daemon_context* daemon, unsigned long id) {
	
	*sock_ctx = (sock_context*)calloc(1, sizeof(sock_context));
	if (*sock_ctx == NULL)
		return -errno;

	(*sock_ctx)->daemon = daemon;
	(*sock_ctx)->id = id;
	(*sock_ctx)->fd = -1; /* standard to show not connected */
	return 0;
}

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data 
 * TODO: this function needs to be updated and debugged */
void sock_context_free(sock_context* sock_ctx) {
	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
	} else { 
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	
	if (sock_ctx->conn != NULL)
		connection_free(sock_ctx->conn);
	free(sock_ctx);
	return;
}



int connection_new(connection** conn) {

	(*conn) = (connection*)calloc(1, sizeof(connection));
	if (*conn == NULL)
		return -errno;

	return 0;
}

/**
 * Closes and frees all of the appropriate file descriptors/structs within a 
 * given sock_context. This function should be called before the connection
 * is set to a different state, as it checks the state to do particular
 * shutdown tasks. This function does not alter state.
 */
void connection_shutdown(sock_context* sock_ctx) {
	
	connection* conn = sock_ctx->conn;

	if (conn->tls != NULL)
		SSL_shutdown(conn->tls);

	if (sock_ctx->listener != NULL) 
		evconnlistener_free(sock_ctx->listener);

	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	conn->secure.bev = NULL;
	conn->secure.closed = 1;
	
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);
	conn->plain.bev = NULL;
	conn->plain.closed = 1;

	if (sock_ctx->fd != -1)
		close(sock_ctx->fd);
	sock_ctx->fd = -1;

	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = NULL;
	
	return;
}

void connection_free(connection* conn) {
	if (conn == NULL) {
		log_printf(LOG_WARNING, "Tried to free a NULL connection.\n");
		return;
	}
	/* This breaks it for some reason...
	 * if (conn->tls != NULL)
	 *     SSL_free(conn->tls);
	*/
	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);
	free(conn);
	return;
}



int associate_fd(connection* conn, evutil_socket_t ifd) {

	if (bufferevent_setfd(conn->plain.bev, ifd) != 0)
		goto err;
	if (bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE) != 0)
		goto err;

	log_printf(LOG_INFO, "plaintext channel bev enabled\n");
	return 0;
 err:
	log_printf(LOG_ERROR, "associate_fd failed.\n");
	return -ENOMEM; /* TODO: choose better errno code? */
}