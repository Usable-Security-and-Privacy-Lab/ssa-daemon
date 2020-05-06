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
 *                       BUFFEREVENT CALLBACK FUNCTIONS
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
 *
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
	long ssl_err;

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

	/* Connection closed--usually due to error or EOF */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		switch (conn->state) {
		case CLIENT_CONNECTING:
			ssl_err = SSL_get_verify_result(conn->tls);

			if (ssl_err != X509_V_OK) {
				/* This error should only be returned on validation failure */
				const char* err_string = X509_verify_cert_error_string(ssl_err);
				log_printf(LOG_ERROR, "Error in validation: %i - %s\n", 
						ssl_err, err_string);
				netlink_handshake_notify_kernel(daemon, id, -EPROTO);
				/* TODO: set SSL error in socket_context here */
			} else {
				/* Errors to do with something other than the validation */
				netlink_handshake_notify_kernel(daemon, id, -ECONNABORTED);
			}

			conn->state = CONN_ERROR;
			break;
		case CLIENT_CONNECTED:
			if (events & BEV_EVENT_ERROR)
				conn->state = CONN_ERROR;
			else
				conn->state = DISCONNECTED;
			break;
		default:
			conn->state = CONN_ERROR;
		}
		connection_shutdown(sock_ctx);
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
	int ret = 0;

	channel* endpoint = (bev == conn->secure.bev) 
			? &conn->plain : &conn->secure;
	channel* startpoint = (bev == conn->secure.bev) 
			? &conn->secure : &conn->plain;



	if (events & BEV_EVENT_CONNECTED) {
		if (conn->state == SERVER_CONNECTING) {
			ret = handle_server_event_connected(conn, startpoint);
			if (ret != 0)
				goto err;
		} else {
			goto err; /* why would there be a connected event otherwise?? */
		}
	}
	if (events & BEV_EVENT_ERROR) {
		handle_event_error(conn, bev_error, startpoint, endpoint);
	}
	if (events & BEV_EVENT_EOF) {
		handle_event_eof(conn, startpoint, endpoint);
	}



	if (endpoint->closed == 1 && startpoint->closed == 1) {
		connection_shutdown(sock_ctx);

		switch (conn->state) {
		case SERVER_CONNECTING:
			/* SSL error led to this */
			conn->state = CONN_ERROR;
			break;
		case SERVER_CONNECTED:
			if (events & BEV_EVENT_ERROR)
				conn->state = CONN_ERROR;
			else
				conn->state = DISCONNECTED;
			break;
		default:
			conn->state = CONN_ERROR;
		}
	}
	return;
 err:
	connection_shutdown(sock_ctx);
	conn->state = CONN_ERROR;
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

void handle_event_error(connection* conn, 
		int error, channel* startpoint, channel* endpoint) {

	int ssl_err;		
	log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", 
			startpoint->bev == conn->secure.bev 
			? "encrypted" : "plaintext");

	
	if (error == ECONNRESET || error == EPIPE) {
		log_printf(LOG_INFO, "Connection closed\n");
	} else {
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