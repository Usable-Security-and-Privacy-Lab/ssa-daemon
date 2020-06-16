#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/ocsp.h>

#include "connection_callbacks.h"
#include "daemon_structs.h"
#include "error.h"
#include "log.h"
#include "netlink.h"
#include "revocation.h"


void handle_client_event_connected(socket_ctx* sock_ctx, 
		daemon_ctx* daemon,	unsigned long id, channel* startpoint);
void handle_server_event_connected(socket_ctx* sock_ctx, channel* startpoint);
void handle_event_error(socket_ctx* sock_ctx, 
		int error, channel* startpoint, channel* endpoint);
void handle_event_eof(socket_ctx* sock_ctx, channel* startpoint, channel* endpoint);
void handle_event_timeout(socket_ctx* sock_ctx);


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
 * @param arg the socket_ctx associated with the given bufferevent.
 */
void common_bev_write_cb(struct bufferevent *bev, void *arg) {

	socket_ctx* sock_ctx = (socket_ctx*) arg;
	channel* endpoint = (bev == sock_ctx->secure.bev) ? &sock_ctx->plain : &sock_ctx->secure;
	
	log_printf(LOG_DEBUG, "write event on bev %p (%s)\n", bev, 
			(bev == sock_ctx->secure.bev) ? "secure" : "plain");

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
 * @param arg the socket_ctx associated with the given bufferevent.
 */
void common_bev_read_cb(struct bufferevent* bev, void* arg) {
	/* TODO: set read high-water mark?? */
	
	socket_ctx* sock_ctx = (socket_ctx*) arg;
	channel* endpoint = (bev == sock_ctx->secure.bev) 
			? &sock_ctx->plain : &sock_ctx->secure;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	log_printf(LOG_DEBUG, "read event on bev %p (%s)\n", bev, 
			(bev == sock_ctx->secure.bev) ? "secure" : "plain");

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

	socket_ctx* sock_ctx = (socket_ctx*) arg;
	daemon_ctx* daemon = sock_ctx->daemon;
	unsigned long id = sock_ctx->id;
	int bev_error = EVUTIL_SOCKET_ERROR();

	channel* endpoint = (bev == sock_ctx->secure.bev)
			? &sock_ctx->plain : &sock_ctx->secure;
	channel* startpoint = (bev == sock_ctx->secure.bev)
			? &sock_ctx->secure : &sock_ctx->plain;


	if (events & BEV_EVENT_CONNECTED)
		handle_client_event_connected(sock_ctx, daemon, id, startpoint);
	
	if (events & BEV_EVENT_ERROR)
		handle_event_error(sock_ctx, bev_error, startpoint, endpoint);
	
	if (events & BEV_EVENT_EOF)
		handle_event_eof(sock_ctx, startpoint, endpoint);
	
	if (events & BEV_EVENT_TIMEOUT) 
		handle_event_timeout(sock_ctx);


	/* Connection closed--usually due to error, EOF or timeout */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		unsigned long ssl_err;
		switch (sock_ctx->state) {
		case SOCKET_CONNECTING:
			ssl_err = bufferevent_get_openssl_error(bev);

            if (ssl_err != 0)
			    set_socket_error(sock_ctx, ssl_err);
			
			socket_shutdown(sock_ctx);
			sock_ctx->state = SOCKET_ERROR;

			netlink_handshake_notify_kernel(daemon, id, -EPROTO);
			break;

		case SOCKET_CONNECTED:
			socket_shutdown(sock_ctx);
			if (events & BEV_EVENT_ERROR)
				sock_ctx->state = SOCKET_ERROR;
			else
				sock_ctx->state = SOCKET_DISCONNECTED;
			break;

		default:
			socket_shutdown(sock_ctx);
			sock_ctx->state = SOCKET_ERROR;
			break;
		}
	}

	return;
}

void server_bev_event_cb(struct bufferevent *bev, short events, void *arg) {

	socket_ctx* sock_ctx = (socket_ctx*) arg;
    int is_secure_channel = (bev == sock_ctx->secure.bev) ? 1 : 0;
	int bev_error = EVUTIL_SOCKET_ERROR();
	
	channel* endpoint = (is_secure_channel) ? &sock_ctx->plain : &sock_ctx->secure;
	channel* startpoint = (is_secure_channel) ? &sock_ctx->secure : &sock_ctx->plain;

	if (events & BEV_EVENT_CONNECTED)
		handle_server_event_connected(sock_ctx, startpoint);
    
    if (events & BEV_EVENT_ERROR)
		handle_event_error(sock_ctx, bev_error, startpoint, endpoint);
	
	if (events & BEV_EVENT_EOF)
		handle_event_eof(sock_ctx, startpoint, endpoint);



	if (endpoint->closed == 1 && startpoint->closed == 1) {

        if (sock_ctx->state == SOCKET_ACCEPTED) {

            /* don't free connection--user has fd reference to it still. */
            socket_shutdown(sock_ctx);
            if (events & BEV_EVENT_ERROR)
                sock_ctx->state = SOCKET_ERROR;
            else 
                sock_ctx->state = SOCKET_DISCONNECTED;

        } else {
			long ssl_err = SSL_get_verify_result(sock_ctx->ssl);
			if (ssl_err != X509_V_OK)
				log_printf(LOG_ERROR, 
                        "TLS handshake error %li on incoming connection: %s",
						ssl_err, X509_verify_cert_error_string(ssl_err));

            hashmap_del(sock_ctx->daemon->sock_map_port, sock_ctx->accept_port);
			socket_context_free(sock_ctx);
        }
	}
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
void handle_client_event_connected(socket_ctx* sock_ctx, 
		daemon_ctx* daemon,	unsigned long id, channel* startpoint) {

	if (startpoint->bev != sock_ctx->secure.bev) {
		log_printf(LOG_WARNING, "Unexpected connect event happened.\n");
		return;
	}

	log_printf(LOG_INFO, "Encrypted endpoint connection negotiated with %s\n", 
			SSL_get_version(sock_ctx->ssl));

	/* BUG: return value of this function never checked */
	bufferevent_set_timeouts(sock_ctx->secure.bev, NULL, NULL);

    sock_ctx->state = SOCKET_FINISHING_CONN;


    if (has_revocation_checks(sock_ctx->rev_ctx.checks))
        do_revocation_checks(sock_ctx);
    else
        netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);
    
    return;
}

/**
 * Handles the case where one of the server channel's bufferevent connected 
 * successfully. If it's the secure channel, we trigger a connection on the
 * plain channel. If it's the plain channel, we don't do much.
 * @param startpoint The channel that triggered the bufferevent.
 * @returns 0 on success, or -errno if an error occurred.
 */
void handle_server_event_connected(socket_ctx* sock_ctx, channel* startpoint) {

	log_printf(LOG_DEBUG, "%s server endpoint connected\n",
		startpoint->bev == sock_ctx->secure.bev ? "Encrypted" : "Plaintext");		

	if (startpoint->bev == sock_ctx->secure.bev) {
		log_printf(LOG_DEBUG, "Now negotiating plaintext connection\n");

		int ret = bufferevent_enable(sock_ctx->plain.bev, EV_READ | EV_WRITE);
		if (ret != 0) 
			goto err;

		ret = bufferevent_socket_connect(sock_ctx->plain.bev, 
				&sock_ctx->int_addr, sock_ctx->int_addrlen);
		if (ret != 0)
			goto err;
	}
	return;
 err:
    log_printf(LOG_DEBUG, "Erasing connection completely\n");
	
    hashmap_del(sock_ctx->daemon->sock_map_port, sock_ctx->accept_port);
	socket_shutdown(sock_ctx);
	socket_context_free(sock_ctx);
}

/**
 * Handles an error event for a given bufferevent and determines whether it
 * will close the bufferevent (by settings startpoint->closed=1 and 
 * endpoint->closed=1) or recover from the error.
 * 
 */
void handle_event_error(socket_ctx* sock_ctx, 
		int error, channel* startpoint, channel* endpoint) {

	log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", 
			startpoint->bev == sock_ctx->secure.bev 
			? "encrypted" : "plaintext");
	
	if (error == ECONNRESET || error == EPIPE) {
		log_printf(LOG_INFO, "Connection closed by local user\n");

	} else if (error != 0) {
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

void handle_event_eof(socket_ctx* sock_ctx, 
		channel* startpoint, channel* endpoint) {

	log_printf(LOG_DEBUG, "%s endpoint got EOF\n", 
				startpoint->bev == sock_ctx->secure.bev ? "encrypted":"plaintext");

	// BUG: when the remote server closes first, this prematurely terminates connections
	// try msn.com and see
	if (bufferevent_getfd(endpoint->bev) == -1)
		endpoint->closed = 1;
	
	else if (endpoint->closed == 0) {
		log_printf(LOG_DEBUG, "Other endpoint not yet closed.\n");
		if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
			log_printf(LOG_DEBUG, "Startpoint buffer size greater than 0.\n");
			common_bev_read_cb(endpoint->bev, sock_ctx);
		}
		if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0) {
			log_printf(LOG_DEBUG, "Startpoint buffer now is 0 size.\n");
			endpoint->closed = 1;
		}
	}

	startpoint->closed = 1;

	return;
}

void handle_event_timeout(socket_ctx* sock_ctx) {

    daemon_ctx* daemon = sock_ctx->daemon;
    int id = sock_ctx->id;

    log_printf(LOG_ERROR, "Connecting bufferevent timed out\n");

    bufferevent_set_timeouts(sock_ctx->secure.bev, NULL, NULL);

    sock_ctx->plain.closed = 1;
    sock_ctx->secure.closed = 1;

    set_err_string(sock_ctx, "TLS handshake error: connection timed out");
    netlink_handshake_notify_kernel(daemon, id, -ENETUNREACH);

    return;
}


