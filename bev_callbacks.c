#include <limits.h>

#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

#include "bev_callbacks.h"
#include "daemon_structs.h"
#include "log.h"
#include "netlink.h"
#include "tls_client.h"



void handle_client_event_connected(sock_context* sock_ctx, 
		daemon_context* daemon,	unsigned long id, channel* startpoint);
int handle_server_event_connected(connection* conn, channel* startpoint);
void handle_event_error(connection* conn, 
		int error, channel* startpoint, channel* endpoint);
void handle_event_eof(connection* conn, channel* startpoint, channel* endpoint);

OCSP_REQUEST* create_ocsp_request(SSL* tls);
int form_http_request(unsigned char **http_req, 
        OCSP_REQUEST *ocsp_req, const char *host, const char *path);
int send_ocsp_request(struct bufferevent* bev, char* url, OCSP_REQUEST* req);

rev_client* get_rev_client(sock_context* sock_ctx, struct bufferevent* bev);
int get_http_body_len(char* response);
int is_bad_http_response(char* response);
int start_reading_body(rev_client* resp);



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
			handle_client_event_connected(sock_ctx, daemon, id, startpoint);
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
		set_err_string(conn, "TLS handshake error: connection timed out");
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
void handle_client_event_connected(sock_context* sock_ctx, 
		daemon_context* daemon,	unsigned long id, channel* startpoint) {

	connection* conn = sock_ctx->conn;		
	int ret;
	
	log_printf(LOG_INFO, "Connected successfully!\n");

	clear_err_string(conn);
	if (startpoint->bev != conn->secure.bev) {
		log_printf(LOG_WARNING, "Unexpected connect event happened.\n");
		return;
	}

	/* BUG: return value of this function never checked */
	bufferevent_set_timeouts(conn->secure.bev, NULL, NULL);

	log_printf(LOG_INFO, "Encrypted endpoint connection negotiated with %s\n", 
			SSL_get_version(conn->tls));


	if (sock_ctx->revocation.state & NO_REVOCATION_CHECKS) {
		/* all done */
		netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);
		return;
	}

	if (!(sock_ctx->revocation.state & NO_OCSP_STAPLED_CHECKS)) {
		ret = check_stapled_response(conn->tls);
		if (ret == V_OCSP_CERTSTATUS_GOOD) {
			log_printf(LOG_INFO, "OCSP Stapled response: good\n");
			netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);
			return;

		} else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
			set_err_string(conn, "TLS handshake error: "
					"certificate revoked (OCSP stapled response)");
			goto err;
		}
	}
	// certificate response is unknown; do other checks (if enabled)

	ret = begin_responder_revocation_checks(sock_ctx);
	if (ret != 0) {
		set_err_string(conn, "TLS handshake error: "
				"could not check peer certificate's revocation status");
		goto err;
	}

	return;
 err:
	conn->state = CONN_ERROR;
	conn->plain.closed = 1;
	conn->secure.closed = 1;
	SSL_shutdown(sock_ctx->conn->tls);
	netlink_handshake_notify_kernel(daemon, id, -EPROTO);
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

	// BUG: when the remote server closes first, this prematurely terminates connections
	// try msn.com and see
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



/*******************************************************************************
 *                   OCSP REVOCATION BEV CALLBACKS
 ******************************************************************************/


void ocsp_responder_read_cb(struct bufferevent* bev, void* arg) {
	
	sock_context* sock_ctx = (sock_context*) arg;
	daemon_context* daemon = sock_ctx->daemon;
	OCSP_BASICRESP* basicresp = NULL;
	rev_client* resp;
	unsigned long id = sock_ctx->id;
	int num_read;
	int ret;

	log_printf(LOG_INFO, "read cb called!\n");

	resp = get_rev_client(sock_ctx, bev);
	if (resp == NULL)
		goto err;

	num_read = bufferevent_read(bev, &resp->buffer[resp->tot_read], 
			resp->buf_size - resp->tot_read);

	resp->tot_read += num_read;

	if (!resp->buffer_is_body) {

		if (strstr((char*)resp->buffer, "\r\n\r\n") != NULL) { 
			ret = start_reading_body(resp);
			if (ret != 0)
				goto err;

		} else if (resp->tot_read == resp->buf_size) {
			goto err;
		}
	}

	if (resp->buffer_is_body && resp->tot_read == resp->buf_size) {

		ret = get_ocsp_basicresp(resp->buffer, resp->tot_read, &basicresp);
		if (ret != 0)
			goto err;

		ret = check_ocsp_response(basicresp, sock_ctx->conn->tls);
		if (ret == V_OCSP_CERTSTATUS_GOOD) {
			log_printf(LOG_INFO, "its good!\n");

			netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);
		
		} else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
			set_err_string(sock_ctx->conn, "TLS handshake error: "
					"certificate revoked (OCSP remote response)");
			
			sock_ctx->conn->state = CONN_ERROR;
			SSL_shutdown(sock_ctx->conn->tls);
			connection_shutdown(sock_ctx);

			netlink_handshake_notify_kernel(daemon, id, -EPROTO);
		} else {
			OCSP_BASICRESP_free(basicresp);
			goto err;
		}

		revocation_context_cleanup(&sock_ctx->revocation);
		OCSP_BASICRESP_free(basicresp);
	}

	return;
 err:
	responder_cleanup(*resp);

	sock_ctx->revocation.num_rev_checks -= 1;
	if (sock_ctx->revocation.num_rev_checks == 0) {
		log_printf(LOG_ERROR, "checks failed.\n");

		set_err_string(sock_ctx->conn, "TLS handshake error: "
				"could not check peer certificate's revocation status");

		revocation_context_cleanup(&sock_ctx->revocation);
		connection_shutdown(sock_ctx);
		sock_ctx->conn->state = CONN_ERROR;

		netlink_handshake_notify_kernel(daemon, id, -EPROTO);
	}
}




void ocsp_responder_event_cb(struct bufferevent* bev, short events, void* arg) {

	sock_context* sock_ctx = (sock_context*) arg;
	SSL* tls = sock_ctx->conn->tls;
	int ret;

	rev_client* resp = get_rev_client(sock_ctx, bev);
	if (resp == NULL)
		return;

	if (events & BEV_EVENT_CONNECTED) {
		OCSP_REQUEST* request = create_ocsp_request(tls);
		if (request == NULL) {
			log_printf(LOG_ERROR, "Create_ocsp_request falied\n");
			goto err;
		}

		ret = send_ocsp_request(bev, resp->url, request);
		if (ret != 0) {
			OCSP_REQUEST_free(request);
			goto err;
		}

		OCSP_REQUEST_free(request);

		ret = bufferevent_enable(bev, EV_READ | EV_WRITE);
		if (ret != 0) {
			log_printf(LOG_ERROR, "bufferevent_enable failed\n");
			goto err;
		}
	}

	// Don't bother with BEV_EVENT_EOF--read_cb or timeout does everything

	if (events & BEV_EVENT_TIMEOUT || events & BEV_EVENT_ERROR) {
		log_printf(LOG_ERROR, "Bufferevent timed out/encountered error\n");
		goto err;
	}
	
	return;
 err:
	log_printf(LOG_ERROR, "Error on ocsp bufferevent\n");

	responder_cleanup(*resp);
	sock_ctx->revocation.num_rev_checks -= 1;
	if (sock_ctx->revocation.num_rev_checks == 0) {
		set_err_string(sock_ctx->conn, "TLS handshake failure: "
				"the certficate's revocation status could not be determined.");

		revocation_context_cleanup(&sock_ctx->revocation);
		connection_shutdown(sock_ctx);
		sock_ctx->conn->state = CONN_ERROR;
		netlink_handshake_notify_kernel(sock_ctx->daemon,
				sock_ctx->id, -EPROTO);
	}
	return;
}


/*******************************************************************************
 *                  OCSP REVOCATION BEV HELPER FUNCTIONS
 ******************************************************************************/


/**
 * Transitions a given responder's buffer and buffer length to reading an HTTP
 * response body (rather than reading the header + body). This function 
 * re-allocates the buffer within resp to the correct size for the body and sets
 * the flag in responder indicating that the buffer contains only the response
 * body.
 * @param resp The given responder to modify the buffer of.
 * @returns 0 on success, or if an error occurred.
 */
int start_reading_body(rev_client* client) {
	log_printf(LOG_INFO, "Called start_reading_body\n");

	unsigned char* body_start;
	int header_len;
	int body_len;

	if (is_bad_http_response((char*) client->buffer))
		return -1;

	body_start = (unsigned char*) strstr((char*) client->buffer, "\r\n\r\n") 
			+ strlen("\r\n\r\n");
	header_len = body_start - client->buffer;

	body_len = get_http_body_len((char*) client->buffer);
	if (body_len < 0)
		return -1;

	unsigned char* tmp_buffer = (unsigned char*) malloc(body_len);
	if (tmp_buffer == NULL)
		return -1;

	client->tot_read -= header_len;
	client->buf_size = body_len;

	memcpy(tmp_buffer, body_start, client->tot_read);
	free(client->buffer);
	client->buffer = tmp_buffer;

	client->buffer_is_body = 1;

	return 0;
}

/**
 * Determines the length of an HTTP response's body, based on the Content-Length
 * field in the HTTP header.
 * @param response the HTTP response to parse the response from.
 * @returns The length of the response body, or -1 on error.
 */
int get_http_body_len(char* response) {

	long body_length;

	char* length_ptr = strstr(response, "Content-Length");
	if (length_ptr == NULL)
		return -1;

	if (length_ptr > strstr(response, "\r\n\r\n"))
		return -1;

	length_ptr += strlen("Content-Length");
	
	while(*length_ptr == ' ' || *length_ptr == ':')
		++length_ptr;

	body_length = strtol(length_ptr, NULL, 10);
	if (body_length >= INT_MAX || body_length < 0)
		return -1;

	return (int) body_length;
}

/**
 * Checks to see if a given response has a a return code.
 * @param response The response to check the HTTP response code of.
 * @returns 0 if the response contains an HTTP 200 code (OK), or 1 otherwise.
 */
int is_bad_http_response(char* response) {

	char* firstline_end = strstr(response, "\r\n");
	char* response_code_ptr = strchr(response, ' ') + 1;
	
	if (response_code_ptr >= firstline_end) 
		return 1;

	long response_code = strtol(response_code_ptr, NULL, 10);
	if (response_code != 200)
		return 1;

	return 0;
}

/**
 * Retrieves the revocation client with the given bufferevent bev from sock_ctx.
 * If used as intended, this function should never return NULL.
 * @param sock_ctx The socket context to search for a revocation client in.
 * @param bev The bufferevent to match with a revocation client.
 * @returns The revocation client of bev; or NULL on failure.
 */
rev_client* get_rev_client(sock_context* sock_ctx, struct bufferevent* bev) {
	
	for (int i = 0; i < sock_ctx->revocation.ocsp_client_cnt; i++) {
		if (bev == sock_ctx->revocation.ocsp_clients[i].bev)
			return &(sock_ctx->revocation.ocsp_clients[i]);
	}

	for (int i = 0; i < sock_ctx->revocation.crl_client_cnt; i++) {
		if (bev == sock_ctx->revocation.crl_clients[i].bev)
			return &(sock_ctx->revocation.crl_clients[i]);
	}

	return NULL;
}

/**
 * Queries an OCSP responder with the given request via an HTTP POST request.
 * @param bev The bufferevent to send the OCSP request through.
 * @param url The url of the OCSP responder.
 * @param id The ID to send an OCSP request for.
 * @returns 0 if the request is being sent, or -1 if an error occurred.
 */
int send_ocsp_request(struct bufferevent* bev, char* url, OCSP_REQUEST* req) {

	unsigned char* http_req = NULL;
	char* host = NULL;
	char* path = NULL;
	int ret, req_len;

	ret = parse_url(url, &host, NULL, &path);
	if (ret != 0)
		goto err;
	
	req_len = form_http_request(&http_req, req, host, path);
	if (req_len < 0) {
		log_printf(LOG_ERROR, "form_http_request failed\n");
		goto err;
	}

	ret = bufferevent_write(bev, http_req, req_len);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Bufferevent_write failed\n");
		goto err;
	}

	free(http_req);
	free(host);
	free(path);
	return 0;
 err:

	if (http_req != NULL)
		free(http_req);
	if (host != NULL)
		free(host);
	if (path != NULL)
		free(path);

	return -1;
}


/**
 * Creates an OCSP Request for the given subject certificate and
 * populates it with all the necessary information needed to query
 * an OCSP Responder. Note that this allocates an OCSP_REQUEST struct
 * that should be freed after use.
 * @param subject The certificate to be checked.
 * @param issuer The parent CA certificate of subject.
 * @returns A pointer to a fully-formed OCSP_REQUEST struct.
 * @see OCSP_REQUEST_free 
 */
OCSP_REQUEST* create_ocsp_request(SSL* tls)
{
    OCSP_REQUEST* request = NULL;
	OCSP_CERTID* id = NULL;

    request = OCSP_REQUEST_new();
    if (request == NULL)
        goto err;

    id = get_ocsp_certid(tls);
	if (id == NULL)
		goto err;

    if (OCSP_request_add0_id(request, id) == NULL)
		goto err;

    return request;
 err:
	OCSP_REQUEST_free(request);
	return NULL;
}


/**
 * Takes in a given OCSP_REQUEST and forms the http request to query the OCSP
 * responder with. The formed request is allocated and stored in *http_req.
 * @returns The length of the request, or -1 if an error occurred.
 */
int form_http_request(unsigned char **http_req, 
        OCSP_REQUEST *ocsp_req, const char *host, const char *path) {

    unsigned char* full_request;
    unsigned char* body = NULL;
    int header_len;
    int body_len;
    char header[MAX_HEADER_SIZE];

    body_len = i2d_OCSP_REQUEST(ocsp_req, &body);
    if (body_len <= 0) {
        log_printf(LOG_ERROR, "Malformed OCSP Request (internal error)\n");
        return -1;
    }

	log_printf(LOG_INFO, "body_len = %i\n", body_len);
    

    header_len = snprintf(header, MAX_HEADER_SIZE, 
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Accept: */*\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Connection: close\r\n"
            "Content-Type: application/ocsp-request\r\n"
            "Content-Length: %i\r\n\r\n",
            path, host, body_len);
    if (header_len < 0 || header_len >= MAX_HEADER_SIZE)
        return -1; /* snprintf failed; or too much header */
	
    
    full_request = calloc(1, header_len + body_len); /* no '\0' */
    if (full_request == NULL) {
		free(body);
        return -1; /* ENOMEM */
	}

    memcpy(full_request, header, header_len);
    memcpy(&full_request[header_len], body, body_len);

    *http_req = full_request;

	free(body);
    return header_len + body_len;
}


/*******************************************************************************
 *                      CRL REVOCATION BEV CALLBACKS
 ******************************************************************************/




