#include <event2/bufferevent.h>
#include <event2/event.h>

#include "error.h"
#include "log.h"
#include "netlink.h"
#include "ocsp.h"
#include "revocation.h"


ocsp_responder* launch_ocsp_client(revocation_ctx* rev_ctx, char* url);
ocsp_responder* get_last_responder(ocsp_responder* list);

OCSP_REQUEST* create_ocsp_request(OCSP_CERTID* id);
int form_http_request(unsigned char **http_req, 
        OCSP_REQUEST *ocsp_req, const char *host, const char *path);
int send_ocsp_request(struct bufferevent* bev, char* url, OCSP_REQUEST* req);

void ocsp_responder_event_cb(struct bufferevent* bev, short events, void* arg);
void ocsp_responder_read_cb(struct bufferevent* bev, void* arg);


/**
 * Parses the AUTHORITY_INFORMATION_ACCESS field out of a given X.509 
 * certificate and returns a list of URLS designating the location of the 
 * OCSP responders.
 * @param cert The X.509 certificate to parse OCSP responder information from.
 * @param num_urls The number of OCSP responder URLs parsed from cert.
 * @returns An allocated array of NULL-terminated strings containing the 
 * URLs of OCSP responders.
 */
char** retrieve_ocsp_urls(X509* cert, int* num_urls) {

	STACK_OF(OPENSSL_STRING) *url_sk = NULL;
	char** urls = NULL;
	url_sk = X509_get1_ocsp(cert);
	if (url_sk == NULL)
		return NULL;

	*num_urls = sk_OPENSSL_STRING_num(url_sk);
	if (*num_urls == 0)
		return NULL;

	urls = calloc(*num_urls, sizeof(char*));
	if (urls == NULL)
		return NULL;

	for (int i = 0; i < *num_urls; i++) 
		urls[i] = sk_OPENSSL_STRING_value(url_sk, i);

	sk_OPENSSL_STRING_free(url_sk);

	return urls;
}


/**
 * Initiates clients to connect to the given OCSP responder URLs and retrieve
 * OCSP revocation responses from them.
 * @param rev_ctx The revocation context that the checks are being performed in.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 * @returns The number of different responders that were successfully queried.
 */
int launch_ocsp_checks(revocation_ctx* rev_ctx, int cert_index, OCSP_CERTID* id) {

    X509* cert = sk_X509_value(rev_ctx->certs, cert_index);
    ocsp_responder* last = NULL;
    ocsp_responder* new_responder;

    char** urls;
    int num_urls;
    int num_responders_queried = 0;

    urls = retrieve_ocsp_urls(cert, &num_urls);
    if (urls == NULL)
        return 0;

    last = get_last_responder(rev_ctx->ocsp_responders);

	for (int i = 0; i < num_urls && i < MAX_OCSP_RESPONDERS; i++) {

        new_responder = launch_ocsp_client(rev_ctx, urls[i]);
        if (new_responder == NULL)
            continue;

        new_responder->certid = OCSP_CERTID_dup(id);
        if (new_responder->certid == NULL) {
            ocsp_responder_free(new_responder);
            continue;
        }

        new_responder->cert_position = cert_index;
        num_responders_queried += 1;

        if (last == NULL)
            rev_ctx->ocsp_responders = new_responder;
         else 
            last->next = new_responder;
            
        last = new_responder;
    }

    if (urls != NULL)
        free(urls);

    return num_responders_queried;
}

/**
 * Traverses through the linked list of responders until it reaches the last
 * responder in the list.
 * @param list A node in the list of responders (can be the beginning, or 
 * somewhere in the middle).
 * @returns The last OCSP responder struct in the list, or NULL if the list
 * was null.
 */
ocsp_responder* get_last_responder(ocsp_responder* list) {

    if (list == NULL)
        return NULL;

    while (list->next != NULL)
        list = list->next;

    return list;
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
ocsp_responder* launch_ocsp_client(revocation_ctx* rev_ctx, char* url) {

    struct timeval read_timeout = { .tv_sec = OCSP_READ_TIMEOUT };
	ocsp_responder* ocsp_resp;
    struct bufferevent* bev = NULL;
	char* hostname = NULL;
	int port;
	int ret;

    ocsp_resp = calloc(1, sizeof(ocsp_responder));
    if (ocsp_resp == NULL) {
        free(url);
        return NULL;
    }

	ocsp_resp->url = url;

    ret = parse_url(url, &hostname, &port, NULL);
	if (ret != 0)
		goto err;

    bev = bufferevent_socket_new(rev_ctx->daemon->ev_base, 
                -1, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL)
        goto err;

    ocsp_resp->bev = bev;

    ret = bufferevent_set_timeouts(bev, &read_timeout, NULL);
    if (ret != 0)
        goto err;

    bufferevent_setcb(bev, ocsp_responder_read_cb, NULL, 
            ocsp_responder_event_cb, (void*) ocsp_resp);

    ret = bufferevent_socket_connect_hostname(bev, 
            rev_ctx->daemon->dns_base, AF_UNSPEC, hostname, port);
    if (ret != 0)
        goto err;

    ocsp_resp->buffer = (unsigned char*) calloc(1, MAX_HEADER_SIZE + 1);
	if (ocsp_resp->buffer == NULL) 
		goto err;

	ocsp_resp->rev_ctx = rev_ctx;
	ocsp_resp->buf_size = MAX_HEADER_SIZE;

	free(hostname);
	return ocsp_resp;
err:
    if (ocsp_resp != NULL)
        ocsp_responder_free(ocsp_resp);

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



/*******************************************************************************
 *                   OCSP REVOCATION BEV CALLBACKS
 ******************************************************************************/


/**
 * The 'event' callback for the responder--gets called when the bufferevent
 * completes the connection, or when an error/timeout occurs.
 * @param bev The bufferevent that the event belongs to.
 * @param events A bitmap of triggered events.
 * @param arg A void pointer to the responder context of the bufferevent.
 */
void ocsp_responder_event_cb(struct bufferevent* bev, short events, void* arg) {

    ocsp_responder* ocsp_resp = (ocsp_responder*) arg;
    revocation_ctx* rev_ctx = ocsp_resp->rev_ctx;
    OCSP_REQUEST* request = NULL;
	int ret;

	if (events & BEV_EVENT_CONNECTED) {
        log_printf(LOG_ERROR, "Received connected event on ocsp responder\n");

		request = create_ocsp_request(ocsp_resp->certid);
		if (request == NULL)
			goto err;

		ret = send_ocsp_request(bev, ocsp_resp->url, request);
		if (ret != 0)
			goto err;

		ret = bufferevent_enable(bev, EV_READ | EV_WRITE);
		if (ret != 0)
			goto err;

        OCSP_REQUEST_free(request);
        request = NULL;
	}

	if (events & BEV_EVENT_TIMEOUT || events & BEV_EVENT_ERROR) {
		log_printf(LOG_ERROR, "Bufferevent timed out/encountered error\n");
		goto err;
	}
        log_printf(LOG_ERROR, "Finished connected event on ocsp responder\n");

	return;
err:
    if (request != NULL)
        OCSP_REQUEST_free(request);

    ocsp_responder_shutdown(ocsp_resp);

	if (rev_ctx->responders_at[ocsp_resp->cert_position]-- == 0) {
		set_err_string(rev_ctx->sock_ctx, "TLS handshake failure: "
				"the certificate's revocation status could not be determined");
        
		fail_revocation_checks(rev_ctx);
	}
}


/**
 * A callback function triggered whenever the read buffer of the bufferevent 
 * receives data. 
 * @param bev The bufferevent that the event is associated with.
 * @param arg A void pointer to the responder context associated with the 
 * bufferevent.
 */
void ocsp_responder_read_cb(struct bufferevent* bev, void* arg) {
	
    ocsp_responder* ocsp_resp = (ocsp_responder*) arg;
	revocation_ctx* rev_ctx = ocsp_resp->rev_ctx;

	int ret, status;
	int num_read;

	num_read = bufferevent_read(bev, &ocsp_resp->buffer[ocsp_resp->tot_read],
			ocsp_resp->buf_size - ocsp_resp->tot_read);

	ocsp_resp->tot_read += num_read;

	if (!ocsp_resp->is_reading_body) {

		if (strstr((char*)ocsp_resp->buffer, "\r\n\r\n") != NULL) {
			ret = start_reading_body(ocsp_resp);
			if (ret != 0)
				goto err;

		} else if (ocsp_resp->tot_read == ocsp_resp->buf_size) {
			goto err;
		}
	}

	/* A connection could be all done reading both header and body in one go */
	if (done_reading_body(ocsp_resp)) {

		status = check_ocsp_response(ocsp_resp->buffer, 
				ocsp_resp->tot_read, rev_ctx, ocsp_resp->certid);

		switch (status) {
		case V_OCSP_CERTSTATUS_UNKNOWN:
			goto err;

		case V_OCSP_CERTSTATUS_GOOD:
            pass_individual_rev_check(ocsp_resp);
			break;

		case V_OCSP_CERTSTATUS_REVOKED:
			set_err_string(rev_ctx->sock_ctx, "TLS handshake error: "
					"certificate revoked (OCSP remote response)");

			fail_revocation_checks(rev_ctx);
			break;
		}
	}

	return;
err:
	ocsp_responder_shutdown(ocsp_resp);

	if (rev_ctx->responders_at[ocsp_resp->cert_position]-- == 0) {
		set_err_string(rev_ctx->sock_ctx, "TLS handshake failure: "
				"the certficate's revocation status could not be determined");

		fail_revocation_checks(rev_ctx);
	}
}

/*******************************************************************************
 *                           HELPER FUNCTIONS
 ******************************************************************************/

/**
 * Creates an OCSP_CERTID for the certificate at the given index in the peer's
 * cert chain.
 * @param rev_ctx The revocation context for the connection (contains the peer's
 * certificate chain).
 * @param cert_index The index of the certificate in the chain to get an 
 * OCSP_CERTID for.
 * @returns A newly allocated OCSP_CERTID, or NULL on failure.
 */
OCSP_CERTID* get_ocsp_certid(revocation_ctx* rev_ctx, int cert_index) {

    X509* subject = sk_X509_value(rev_ctx->certs, cert_index);
    X509* issuer = sk_X509_value(rev_ctx->certs, cert_index + 1);

    return OCSP_cert_to_id(NULL, subject, issuer);
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
OCSP_REQUEST* create_ocsp_request(OCSP_CERTID* id) {
    OCSP_REQUEST* request = NULL;

    id = OCSP_CERTID_dup(id);
    if (id == NULL)
        goto err;

    request = OCSP_REQUEST_new();
    if (request == NULL)
        goto err;

    if (OCSP_request_add0_id(request, id) == NULL)
		goto err;

    return request;
err:
    if (request != NULL)
	    OCSP_REQUEST_free(request);
    else
        OCSP_CERTID_free(id);

    return NULL;
}


/**
 * Converts a given array of bytes into an OCSP_RESPONSE, checks its validity,
 * and extracts the basic response found within the response.
 * @param bytes The given bytes to convert.
 * @param len The length of bytes.
 * @param resp The OCSP basic response structure extracted from bytes.
 * @returns 0 on success, or -1 if an error occurred.
 */
int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp) {

	OCSP_RESPONSE* full_response = NULL;
	const unsigned char* const_bytes = bytes;
	int ret;

	full_response = d2i_OCSP_RESPONSE(NULL, &const_bytes, (long)len);
	if (full_response == NULL)
		goto err;

	ret = OCSP_response_status(full_response);
	if (ret != OCSP_RESPONSE_STATUS_SUCCESSFUL)
		goto err;

	*resp = OCSP_response_get1_basic(full_response);
	if (*resp == NULL)
		goto err;

	OCSP_RESPONSE_free(full_response);
	return 0;
err:
	if (full_response != NULL)
		OCSP_RESPONSE_free(full_response);

	return -1;
}