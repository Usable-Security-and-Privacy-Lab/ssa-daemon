#include "daemon_structs.h"

#include "log.h"
#include "event2/bufferevent.h"
#include "event2/listener.h"



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

/* TODO: Finish this function */
/*
int sock_context_reset(sock_context* sock_ctx) {

	connection* conn = sock_ctx->conn;

	if (conn != NULL) {
		connection_shutdown(sock_ctx->conn);
		conn->addr = NULL;
		conn->addrlen = 0;
	}

	sock_ctx->fd = -1;

	set_client(sock_ctx->state);
	set_disconnected(sock_ctx->state);
	set_not_accepting(sock_ctx->state);
	set_unbound(sock_ctx->state);
	set_not_custom_validation(sock_ctx->state);


	return -1; 
}
*/

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data 
 * TODO: this function needs to be updated and debugged */
void sock_context_free(sock_context* sock_ctx) {
	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
	} else if (is_connected(sock_ctx->state)) {
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
	} else { 
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	
	if (sock_ctx->conn != NULL)
		connection_free(sock_ctx->conn);
	free(sock_ctx);
	return;
}



int connection_new(connection** conn) {

	*conn = (connection*)calloc(1, sizeof(connection));
	if (*conn == NULL)
		return -errno;

	return 0;
}

void connection_shutdown(connection* conn) {
	
	SSL_shutdown(conn->tls);

	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	conn->secure.bev = NULL;
	
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);
	conn->plain.bev = NULL;

	/* conn->tls is automatically freed by bufferevent */
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
	return -1; /* No return info available; lookup libevent log */
}