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

#define MAX_HEADER_SIZE 8192

#define MAX_OCSP_RESPONDERS 5
#define OCSP_READ_TIMEOUT 8



void handle_client_event_connected(socket_ctx* sock_ctx, 
		daemon_ctx* daemon,	unsigned long id, channel* startpoint);
void handle_server_event_connected(socket_ctx* sock_ctx, channel* startpoint);
void handle_event_error(socket_ctx* sock_ctx, 
		int error, channel* startpoint, channel* endpoint);
void handle_event_eof(socket_ctx* sock_ctx, channel* startpoint, channel* endpoint);
void handle_event_timeout(socket_ctx* sock_ctx);


void ocsp_responder_read_cb(struct bufferevent* bev, void* arg);
void ocsp_responder_event_cb(struct bufferevent* bev, short events, void* arg);

// Revocation-specific helper functions

int launch_ocsp_checks(socket_ctx* sock_ctx, char** urls, int num_urls);
int launch_crl_checks(socket_ctx* sock_ctx, char** urls, int num_urls);
int launch_ocsp_client(socket_ctx* sock_ctx, char* url);


void ocsp_dns_cb(int result, struct evutil_addrinfo* res, void* arg);

responder_ctx* get_responder_ctx(socket_ctx* sock_ctx, struct bufferevent* bev);

OCSP_REQUEST* create_ocsp_request(SSL* ssl);
int form_http_request(unsigned char **http_req, 
        OCSP_REQUEST *ocsp_req, const char *host, const char *path);
int send_ocsp_request(struct bufferevent* bev, char* url, OCSP_REQUEST* req);

int is_bad_http_response(char* response);
int get_http_body_len(char* response);
int start_reading_body(responder_ctx* resp_ctx);
int done_reading_body(responder_ctx* resp_ctx);

void fail_revocation_checks(socket_ctx* sock_ctx);




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


	if (sock_ctx->revocation.checks & NO_REVOCATION_CHECKS
            || sock_ctx->revocation.state == REV_S_PASS) {

		netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);

	} else if (sock_ctx->revocation.state == REV_S_FAIL) {
        socket_shutdown(sock_ctx);
        sock_ctx->state = SOCKET_ERROR;

        netlink_handshake_notify_kernel(daemon, id, -EPROTO);
    }
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
				sock_ctx->addr, sock_ctx->addrlen);
		if (ret != 0)
			goto err;
	}
	return;
 err:
    log_printf(LOG_DEBUG, "Erasing connection completely\n");
	
    hashmap_del(sock_ctx->daemon->sock_map_port, get_port(&sock_ctx->int_addr));
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


/*******************************************************************************
 *                   OCSP REVOCATION BEV CALLBACKS
 ******************************************************************************/


void ocsp_responder_read_cb(struct bufferevent* bev, void* arg) {
	
    responder_ctx* resp_ctx = (responder_ctx*) arg;
	socket_ctx* sock_ctx = resp_ctx->sock_ctx;

	revocation_ctx* rev_ctx = &sock_ctx->revocation;
	daemon_ctx* daemon = sock_ctx->daemon;
	unsigned long id = sock_ctx->id;

	int ret, status;
	int num_read;

	num_read = bufferevent_read(bev, &resp_ctx->buffer[resp_ctx->tot_read], 
			resp_ctx->buf_size - resp_ctx->tot_read);

	resp_ctx->tot_read += num_read;

	if (!resp_ctx->reading_body) {

		if (strstr((char*)resp_ctx->buffer, "\r\n\r\n") != NULL) {
			ret = start_reading_body(resp_ctx);
			if (ret != 0)
				goto err;

		} else if (resp_ctx->tot_read == resp_ctx->buf_size) {
			goto err;
		}
	}

	/* A connection could be all done reading both header and body in one go */
	if (done_reading_body(resp_ctx)) {
		status = do_ocsp_response_checks(resp_ctx->buffer, 
				resp_ctx->tot_read, sock_ctx);

		switch (status) {
		case V_OCSP_CERTSTATUS_UNKNOWN:
			goto err;

		case V_OCSP_CERTSTATUS_GOOD:
			revocation_context_cleanup(rev_ctx);
			netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);
			break;

		case V_OCSP_CERTSTATUS_REVOKED:
			set_err_string(sock_ctx, "TLS handshake error: "
					"certificate revoked (OCSP remote response)");
			
			fail_revocation_checks(sock_ctx);
			break;
		}
	}

	return;
 err:
	responder_cleanup(resp_ctx);

	if (rev_ctx->num_rev_checks-- == 0) {
		set_err_string(sock_ctx, "TLS handshake failure: "
				"the certficate's revocation status could not be determined");

		fail_revocation_checks(sock_ctx);
	}
}


void ocsp_responder_event_cb(struct bufferevent* bev, short events, void* arg) {

    responder_ctx* resp_ctx = (responder_ctx*) arg;
	socket_ctx* sock_ctx = resp_ctx->sock_ctx;
	SSL* ssl = sock_ctx->ssl;
	OCSP_REQUEST* request = NULL;
	int ret;

	if (events & BEV_EVENT_CONNECTED) {
		OCSP_REQUEST* request = create_ocsp_request(ssl);
		if (request == NULL)
			goto err;

		ret = send_ocsp_request(bev, resp_ctx->url, request);
		if (ret != 0)
			goto err;

		ret = bufferevent_enable(bev, EV_READ | EV_WRITE);
		if (ret != 0)
			goto err;

		OCSP_REQUEST_free(request);
	}

	if (events & BEV_EVENT_TIMEOUT || events & BEV_EVENT_ERROR) {
		log_printf(LOG_ERROR, "Bufferevent timed out/encountered error\n");
		goto err;
	}

	return;
 err:
	if (request != NULL)
		OCSP_REQUEST_free(request);
	
	responder_cleanup(resp_ctx);

	if (sock_ctx->revocation.num_rev_checks-- == 0) {
		set_err_string(sock_ctx, "TLS handshake failure: "
				"the certificate's revocation status could not be determined");

		fail_revocation_checks(sock_ctx);
	}
}


/*******************************************************************************
 *                  OCSP REVOCATION BEV HELPER FUNCTIONS
 ******************************************************************************/


/**
 * Performs the desired revocation checks on a given connection
 * @param sock_ctx The connection to perform checks on.
 * @returns 0 if the checks were successfully started, -1 if no distribution 
 * points were found (and/or if the responder revocation methods are disabled),
 * or -2 if an unrecoverable error occurred.
 */
int revocation_cb(SSL* ssl, void* arg) {

    socket_ctx* sock_ctx = (void*) arg;
	X509* cert;
	char** ocsp_urls = NULL;
	char** crl_urls = NULL;
	int ocsp_url_cnt = 0;
	int crl_url_cnt = 0;
    int ret;


    ret = check_cached_response(sock_ctx);
	if (ret == V_OCSP_CERTSTATUS_GOOD) {
		log_printf(LOG_INFO, "OCSP cached response: good\n");
        set_revocation_state(sock_ctx, REV_S_PASS);
		return 1;

	} else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
		set_err_string(sock_ctx, "TLS handshake error: "
				"certificate revoked (cached OCSP response)");
        set_revocation_state(sock_ctx, REV_S_FAIL);
        return 1;

	} else {
		log_printf(LOG_INFO, "No cached revocation response were found\n");
	}

	if (!(sock_ctx->revocation.checks & NO_OCSP_STAPLED_CHECKS)) {
		ret = check_stapled_response(sock_ctx);
		if (ret == V_OCSP_CERTSTATUS_GOOD) {
			log_printf(LOG_INFO, "OCSP Stapled response: good\n");
            set_revocation_state(sock_ctx, REV_S_PASS);
			return 1;

		} else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
			set_err_string(sock_ctx, "TLS handshake error: "
					"certificate revoked (OCSP stapled response)");
            set_revocation_state(sock_ctx, REV_S_FAIL);
			return 1;
		}
	}

    cert = SSL_get_peer_certificate(sock_ctx->ssl);
    if (cert == NULL)
        goto err;

    if (!(sock_ctx->revocation.checks & NO_OCSP_RESPONDER_CHECKS))
        ocsp_urls = retrieve_ocsp_urls(cert, &ocsp_url_cnt);

    if (!(sock_ctx->revocation.checks & NO_CRL_RESPONDER_CHECKS))
        crl_urls = retrieve_crl_urls(cert, &crl_url_cnt);


    if (ocsp_url_cnt > 0)
		launch_ocsp_checks(sock_ctx, ocsp_urls, ocsp_url_cnt);

	if (crl_url_cnt > 0)
        launch_crl_checks(sock_ctx, crl_urls, crl_url_cnt);

    if (sock_ctx->revocation.num_rev_checks == 0)
        goto err;


    if (ocsp_urls != NULL)
        free(ocsp_urls);
    if (crl_urls != NULL)
        free(crl_urls);

    X509_free(cert);

    return 1;
 err:
    if (cert != NULL)
        X509_free(cert);

    if (ocsp_urls != NULL)
        free(ocsp_urls);
    if (crl_urls != NULL)
        free(crl_urls);

    set_err_string(sock_ctx, "TLS handshake error: "
            "no revocation responders could be queried");
    set_revocation_state(sock_ctx, REV_S_FAIL);
    return 1;
}

/**
 * Initiates clients to connect to the given OCSP responder URLs and retrieve
 * OCSP revocation responses from them.
 * @param sock_ctx The socket context that the checks are being performed
 * on behalf of.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 */
int launch_ocsp_checks(socket_ctx* sock_ctx, char** urls, int num_urls) {

	revocation_ctx* rev = &sock_ctx->revocation;

	rev->ocsp_clients = calloc(MAX_OCSP_RESPONDERS, sizeof(responder_ctx));
	if (rev->ocsp_clients == NULL)
		return 0;


	for (int i = 0; i < num_urls && i < MAX_OCSP_RESPONDERS; i++)
		launch_ocsp_client(sock_ctx, urls[i]);

	if (rev->ocsp_client_cnt == 0)
		return -1;

	return 0;
}

/**
 * Creates a new bufferevent and initiates an HTTP connection with the server 
 * specified by url. On success, the information about the given connection 
 * (such as the bufferevent and the url) is stored in the revocation context
 * of the given socket context.
 * @param sock_ctx The given socket context to initiate an OCSP client for.
 * @param url The URL of the OCSP responder for the client to connect to.
 * @returns 0 on success, or -1 if an error occurred.
 */
int launch_ocsp_client(socket_ctx* sock_ctx, char* url) {

	revocation_ctx* rev = &sock_ctx->revocation;
	responder_ctx* ocsp_client = &rev->ocsp_clients[rev->ocsp_client_cnt];
    struct bufferevent* bev = NULL;
	char* hostname = NULL;
	int port;
	int ret;

    struct timeval read_timeout = {
		.tv_sec = OCSP_READ_TIMEOUT,
		.tv_usec = 0,
	};

	ret = parse_url(url, &hostname, &port, NULL);
	if (ret != 0)
		goto err;


    bev = bufferevent_socket_new(sock_ctx->daemon->ev_base, 
            -1, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL)
        goto err;

    ret = bufferevent_set_timeouts(bev, &read_timeout, NULL);
    if (ret != 0)
        goto err;

    bufferevent_setcb(bev, ocsp_responder_read_cb, NULL, 
            ocsp_responder_event_cb, (void*) ocsp_client);

    ret = bufferevent_socket_connect_hostname(bev, 
            sock_ctx->daemon->dns_base, AF_UNSPEC, hostname, port);
    if (ret != 0)
        goto err;

    ocsp_client->buffer = (unsigned char*) calloc(1, MAX_HEADER_SIZE + 1);
	if (ocsp_client->buffer == NULL) 
		goto err;

    ocsp_client->bev = bev;
	ocsp_client->sock_ctx = sock_ctx;
	ocsp_client->buf_size = MAX_HEADER_SIZE;
	ocsp_client->url = url;
		
	rev->num_rev_checks++;
	rev->ocsp_client_cnt++;

	free(hostname);
	return 0;
 err:
    if (bev != NULL)
        bufferevent_free(bev);
    if (hostname != NULL)
		free(hostname);
	if (ocsp_client->buffer != NULL)
		free(ocsp_client->buffer);

	return -1;
}


void fail_revocation_checks(socket_ctx* sock_ctx) {

    sock_ctx->revocation.state = REV_S_FAIL;
	revocation_context_cleanup(&sock_ctx->revocation);

    if (sock_ctx->state != SOCKET_CONNECTING) {
	    socket_shutdown(sock_ctx);
        sock_ctx->state = SOCKET_ERROR;
        netlink_handshake_notify_kernel(sock_ctx->daemon, sock_ctx->id, -EPROTO);
    }
}


/*******************************************************************************
 *              HELPER FUNCTIONS FOR OCSP HTTP CONNECTION
 ******************************************************************************/


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
 * Transitions a given responder's buffer and buffer length to reading an HTTP
 * response body (rather than reading the header + body). This function 
 * re-allocates the buffer within resp_ctx to the correct size for the body and sets
 * the flag in responder indicating that the buffer contains only the response
 * body.
 * @param resp_ctx The given responder to modify the buffer of.
 * @returns 0 on success, or if an error occurred.
 */
int start_reading_body(responder_ctx* client) {

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

	client->reading_body = 1;

	return 0;
}

int done_reading_body(responder_ctx* resp_ctx) {

	return resp_ctx->reading_body && (resp_ctx->tot_read == resp_ctx->buf_size);
}



/*******************************************************************************
 *                      CRL REVOCATION BEV CALLBACKS
 ******************************************************************************/




/**
 * Initiates clients to connect to the given CRL responder URLs and retreive
 * Certificate Revocation Lists (CRLs) from them.
 * @param sock_ctx The socket context that the checks are being performed
 * on behalf of.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 */
int launch_crl_checks(socket_ctx* sock_ctx, char** urls, int num_urls) {

	for (int i = 0; i < num_urls; i++) {
		//char* url = crl_urls[i];

		//set up bufferevent here (with timeout),
		//pass in callbacks (with revocation_ctx* as the (void*) arg)
		//start the bufferevent's connection
	}

	return 0; // TODO: stub
}


