#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>


#include "bev_callbacks.h"
#include "daemon_structs.h"
#include "log.h"
#include "netlink.h"



void handle_client_event_connected(connection* conn, 
		daemon_context* daemon,	unsigned long id, channel* startpoint);
int handle_server_event_connected(connection* conn, channel* startpoint);
void handle_event_error(connection* conn, 
		int error, channel* startpoint, channel* endpoint);
void handle_event_eof(connection* conn, channel* startpoint, channel* endpoint);




/*
 *******************************************************************************
 *                  CONNECTION BUFFEREVENT CALLBACK FUNCTIONS
 *******************************************************************************
 */

/**
 * Bufferevents automatically read data in from their fd to their read buffer,
 * as well as reading data out from their write buffer to their fd. All that
 * these callbacks to is notify you when these read/write operations have been
 * triggered. Since we don't modify the watermarks of the read_cb, it is 
 * triggered every time new information is read in from a file descriptor, and
 * never stops reading. 
 * This write_cb has functionality that works in tandem with the read callback;
 * when too much data has been put into the write buffer (out_buf >= MAX_BUFFER)
 * the read_cb temporarily disables itself from reading in new data and sets
 * the other bufferevent's writing watermarks so that it will not trigger
 * a write callback until half of that data has been written out. Once that
 * happens, the write_cb re-enables the other bufferevent's reading capabilities
 * and resets its own writing watermarks to 0, so that its write_cb will not be
 * triggered until no data is left to be written.
 * Note that this function is not called every time a write operation occurs, 
 * and it certainly does not cause data to be written from the write buffer to
 * the fd. It merely reports once all data to be written from a buffer has been
 * written.
 * @param bev The bufferevent that triggered the write callback.
 * @param arg the sock_context associated with the given bufferevent.
 */
void common_bev_write_cb(struct bufferevent *bev, void *arg) {

	connection* conn = ((sock_context*)arg)->conn;
	channel* endpoint = (bev == conn->secure.bev) ? &conn->plain : &conn->secure;
	
	log_printf(LOG_DEBUG, "write event on bev %p (%s)\n", bev, 
			(bev == conn->secure.bev) ? "secure" : "plain");

	if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint->bev, EV_READ);
	}
	return;
}

/**
 * Every time data is read into a bufferevent from its associated fd, this
 * function will be called. It takes that data and writes it to the write buffer
 * of the other bufferevent. If too much data is being fed through, the read 
 * operation of this bufferevent will be turned off until the other buffer has
 * written enough data out.
 * @param bev The bufferevent that triggered the read callback.
 * @param arg the sock_context associated with the given bufferevent.
 */
void common_bev_read_cb(struct bufferevent* bev, void* arg) {
	/* TODO: set read high-water mark?? */
	
	connection* conn = ((sock_context*)arg)->conn;
	channel* endpoint = (bev == conn->secure.bev) 
			? &conn->plain : &conn->secure;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	log_printf(LOG_DEBUG, "read event on bev %p (%s)\n", bev, 
			(bev == conn->secure.bev) ? "secure" : "plain");

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	if (in_len == 0)
		return;

	/* clear read buffer if already closed */
	if (endpoint->closed == 1) {
		log_printf(LOG_DEBUG, "drained buffer.\n");
		evbuffer_drain(in_buf, in_len);
		return;
	}

	/* copy content to the output buffer of the other bufferevent */
	out_buf = bufferevent_get_output(endpoint->bev);
	evbuffer_add_buffer(out_buf, in_buf);

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint->bev, 
				EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void client_bev_event_cb(struct bufferevent *bev, short events, void *arg) {

	sock_context* sock_ctx = (sock_context*) arg;
	daemon_context* daemon = sock_ctx->daemon;
	connection* conn = sock_ctx->conn;
	unsigned long id = sock_ctx->id;
	int bev_error = EVUTIL_SOCKET_ERROR();

	channel* endpoint = (bev == conn->secure.bev) 
			? &conn->plain : &conn->secure;
	channel* startpoint = (bev == conn->secure.bev) 
			? &conn->secure : &conn->plain;

	if (events & BEV_EVENT_CONNECTED) {
		if (conn->state == CLIENT_CONNECTING)
			handle_client_event_connected(conn, daemon, id, startpoint);
		else
			goto err; /* why would there be a connected event otherwise?? */
	}
	if (events & BEV_EVENT_ERROR) {
		handle_event_error(conn, bev_error, startpoint, endpoint);
	}
	if (events & BEV_EVENT_EOF) {
		handle_event_eof(conn, startpoint, endpoint);
	}
	if (events & BEV_EVENT_TIMEOUT) {
		/* case where connection to external timed out */
		log_printf(LOG_ERROR, "Connecting bufferevent timed out\n");

		endpoint->closed = 1;
		startpoint->closed = 1;
		conn->state = CONN_ERROR;
		bufferevent_set_timeouts(conn->secure.bev, NULL, NULL);
		netlink_handshake_notify_kernel(daemon, id, -ENETUNREACH);
	}

	/* Connection closed--usually due to error or EOF */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		unsigned long ssl_err;
		switch (conn->state) {
		case CLIENT_CONNECTING:
			ssl_err = bufferevent_get_openssl_error(bev);

			set_verification_err_string(conn, ssl_err);
			netlink_handshake_notify_kernel(daemon, id, -EPROTO);
			
			connection_shutdown(sock_ctx);
			conn->state = CONN_ERROR;
			break;
		case CLIENT_CONNECTED:
			connection_shutdown(sock_ctx);
			if (events & BEV_EVENT_ERROR)
				conn->state = CONN_ERROR;
			else
				conn->state = DISCONNECTED;
			break;
		default:
			connection_shutdown(sock_ctx);
			conn->state = CONN_ERROR;
			break;
		}

	}

	return;
 err:
	connection_shutdown(sock_ctx);
	conn->state = CONN_ERROR;
	return;
}

void server_bev_event_cb(struct bufferevent *bev, short events, void *arg) {

	sock_context* sock_ctx = (sock_context*) arg;
	connection* conn = sock_ctx->conn;
	int bev_error = EVUTIL_SOCKET_ERROR();
	int ret;
	int is_secure_channel = (bev == conn->secure.bev) ? 1 : 0;

	channel* endpoint = (is_secure_channel) 
			? &conn->plain : &conn->secure;
	channel* startpoint = (is_secure_channel) 
			? &conn->secure : &conn->plain;


	if (events & BEV_EVENT_CONNECTED) {
		if (conn->state == SERVER_CONNECTING) {
			ret = handle_server_event_connected(conn, startpoint);
			if (ret != 0)
				goto err;
		} else {
			log_printf(LOG_ERROR, "Unexpected CONNECT event on bev %p\n", bev);
		}
	}
	if (events & BEV_EVENT_ERROR) {
		handle_event_error(conn, bev_error, startpoint, endpoint);
	}
	if (events & BEV_EVENT_EOF) {
		handle_event_eof(conn, startpoint, endpoint);
	}


	if (endpoint->closed == 1 && startpoint->closed == 1) {
		log_printf(LOG_DEBUG, "Closed both endpoints\n");

		if (conn->state == SERVER_CONNECTING) {
			log_printf(LOG_DEBUG, "Made it here\n");
			long ssl_err = SSL_get_verify_result(conn->tls);
			if (ssl_err != X509_V_OK)
				log_printf(LOG_ERROR, 
						"TLS handshake error %li on incoming connection: %s",
						ssl_err, X509_verify_cert_error_string(ssl_err));

			goto err; /* No need to save the connection--the user doesn't 
			           * know it happened and doesn't have ref to it */
		}

		/* don't free connection--user has fd reference to it still. */
		connection_shutdown(sock_ctx);
		if (events & BEV_EVENT_ERROR)
			conn->state = CONN_ERROR;
		else 
			conn->state = DISCONNECTED;
	}
	return;
 err:
	log_printf(LOG_DEBUG, "Freeing connection completely\n");
	/* completely frees the connection */
	hashmap_del(sock_ctx->daemon->sock_map_port, get_port(&sock_ctx->int_addr));
	connection_shutdown(sock_ctx);
	sock_context_free(sock_ctx); /* TODO: test this by using client with bad ciphers */
	return;
}

/*
 *******************************************************************************
 *                   BUFFEREVENT CALLBACK HELPER FUNCTIONS
 *******************************************************************************
 */

/**
 * Handles the case where the client channel's secure bufferevent connected 
 * successfully; this is not called when the plain channel is connected. 
 * When accept_cb is called, the socket passed in is already connected,
 * so when it is associated with the plain channel bufferevent 
 * (in associate_fd()) it will not trigger the connected event.
 * @param conn The connection context associated with the triggered bufferevent.
 * @param daemon The daemon's context.
 * @param id The id of the socket context associated with this bufferevent.
 * @param startpoint The channel that triggered the bufferevent.
 */
void handle_client_event_connected(connection* conn, 
		daemon_context* daemon,	unsigned long id, channel* startpoint) {

	if (startpoint->bev != conn->secure.bev) {
		log_printf(LOG_WARNING, "Unexpected connect event happened.\n");
		return;
	}
	/* TODO: test SSL_get_peer_certificate() == NULL */

	/* BUG: return value of this function never checked */
	bufferevent_set_timeouts(conn->secure.bev, NULL, NULL);

	log_printf(LOG_INFO, "Encrypted endpoint connection negotiated with %s\n", 
			SSL_get_version(conn->tls));

	netlink_handshake_notify_kernel(daemon, id, 0);
	return;
}

/**
 * Handles the case where one of the server channel's bufferevent connected 
 * successfully. If it's the secure channel, we trigger a connection on the
 * plain channel. If it's the plain channel, we don't do much.
 * @param startpoint The channel that triggered the bufferevent.
 * @returns 0 on success, or -errno if an error occurred.
 */
int handle_server_event_connected(connection* conn, channel* startpoint) {

	log_printf(LOG_DEBUG, "%s server endpoint connected\n",
		startpoint->bev == conn->secure.bev ? "Encrypted" : "Plaintext");		

	if (startpoint->bev == conn->secure.bev) {
		log_printf(LOG_DEBUG, "Now negotiating plaintext connection\n");

		int ret = bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);
		if (ret != 0) 
			return -1;

		ret = bufferevent_socket_connect(conn->plain.bev, 
				conn->addr, conn->addrlen);
		if (ret != 0)
			return -1;
	}
	return 0;
}

/**
 * Handles an error event for a given bufferevent and determines whether it
 * will close the bufferevent (by settings startpoint->closed=1 and 
 * endpoint->closed=1) or recover from the error.
 * 
 */
void handle_event_error(connection* conn, 
		int error, channel* startpoint, channel* endpoint) {

	log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", 
			startpoint->bev == conn->secure.bev 
			? "encrypted" : "plaintext");
	
	if (error == ECONNRESET || error == EPIPE) {
		log_printf(LOG_INFO, "Connection closed by local user\n");
	} else if (error != 0){
		log_printf(LOG_WARNING, "Unhandled error %i has occurred: %s\n", 
				error, evutil_socket_error_to_string(error));
	}

	startpoint->closed = 1;

	if (endpoint->closed == 0) {
		struct evbuffer* out_buf;
		out_buf = bufferevent_get_output(endpoint->bev);
		/* close other buffer if we're closing and it has no data left */
		if (evbuffer_get_length(out_buf) == 0)
			endpoint->closed = 1;
	}
	return;
}

void handle_event_eof(connection* conn, 
		channel* startpoint, channel* endpoint) {

	log_printf(LOG_DEBUG, "%s endpoint got EOF\n", 
				startpoint->bev == conn->secure.bev ? "encrypted":"plaintext");

	if (bufferevent_getfd(endpoint->bev) == -1)
		endpoint->closed = 1;
	
	else if (endpoint->closed == 0) {
		log_printf(LOG_DEBUG, "Other endpoint not yet closed.\n");
		if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
			log_printf(LOG_DEBUG, "Startpoint buffer size greater than 0.\n");
			common_bev_read_cb(endpoint->bev, conn);
		}
		if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0) {
			log_printf(LOG_DEBUG, "Startpoint buffer now is 0 size.\n");
			endpoint->closed = 1;
		}
	}
	startpoint->closed = 1;

	return;
}