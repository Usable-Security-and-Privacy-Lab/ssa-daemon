#include <string.h>

#include <event2/bufferevent.h>

#include "crl.h"
#include "error.h"
#include "log.h"
#include "netlink.h"
#include "ocsp.h"
#include "revocation.h"

int check_stapled_response(socket_ctx* sock_ctx);


/**
 * Performs the desired revocation checks on a given connection
 * @param sock_ctx The connection to perform checks on.
 */
void do_revocation_checks(socket_ctx *sock_ctx) {

	X509* cert;
	char** ocsp_urls = NULL;
	char** crl_urls = NULL;
	int ocsp_url_cnt = 0;
	int crl_url_cnt = 0;
    int ret;

    if (has_cached_checks(sock_ctx->rev_ctx.checks)) {

        ret = check_cached_response(sock_ctx);

        if (ret == V_OCSP_CERTSTATUS_GOOD) {
            log_printf(LOG_INFO, "OCSP cached response: good\n");
            pass_revocation_checks(sock_ctx);
            return;

        } else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
            set_err_string(sock_ctx, "TLS handshake error: "
                    "certificate revoked (cached OCSP response)");
            fail_revocation_checks(sock_ctx);
            return;

        } else {
            log_printf(LOG_INFO, "No cached revocation response were found\n");
        }
    }

	if (has_stapled_checks(sock_ctx->rev_ctx.checks)) {

		ret = check_stapled_response(sock_ctx);

		if (ret == V_OCSP_CERTSTATUS_GOOD) {
			log_printf(LOG_INFO, "OCSP Stapled response: good\n");
            pass_revocation_checks(sock_ctx);
			return;

		} else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
			set_err_string(sock_ctx, "TLS handshake error: "
					"certificate revoked (OCSP stapled response)");
            fail_revocation_checks(sock_ctx);
			return;
		}
	}

    cert = SSL_get_peer_certificate(sock_ctx->ssl);
    if (cert == NULL) {
        set_err_string(sock_ctx, "TLS handshake error: "
                "could not get peer certificate");
        fail_revocation_checks(sock_ctx);
        return;
    }


    if (has_ocsp_checks(sock_ctx->rev_ctx.checks))
        ocsp_urls = retrieve_ocsp_urls(cert, &ocsp_url_cnt);

    if (has_crl_checks(sock_ctx->rev_ctx.checks))
        crl_urls = retrieve_crl_urls(cert, &crl_url_cnt);


    if (ocsp_url_cnt > 0)
		launch_ocsp_checks(sock_ctx, ocsp_urls, ocsp_url_cnt);

	if (crl_url_cnt > 0)
        launch_crl_checks(sock_ctx, crl_urls, crl_url_cnt);

    if (sock_ctx->rev_ctx.num_rev_checks == 0) {
        set_err_string(sock_ctx, "TLS handshake error: "
                "no revocation response could be obtained");
        fail_revocation_checks(sock_ctx);
    }


    if (ocsp_urls != NULL)
        free(ocsp_urls);
    if (crl_urls != NULL)
        free(crl_urls);

    X509_free(cert);
    return;
}



void pass_revocation_checks(socket_ctx *sock_ctx) {

    sock_ctx->rev_ctx.state = REV_S_PASS;
    revocation_context_cleanup(&sock_ctx->rev_ctx);

    netlink_handshake_notify_kernel(sock_ctx->daemon, sock_ctx->id, NOTIFY_SUCCESS);
}

void fail_revocation_checks(socket_ctx* sock_ctx) {

    sock_ctx->rev_ctx.state = REV_S_FAIL;
	revocation_context_cleanup(&sock_ctx->rev_ctx);

    socket_shutdown(sock_ctx);
    sock_ctx->state = SOCKET_ERROR;
    netlink_handshake_notify_kernel(sock_ctx->daemon, sock_ctx->id, -EPROTO);
}


/*******************************************************************************
 *   FUNCTIONS TO CHECK AN OCSP RESPONSE (STAPLED, CACHED OR WHAT HAVE YOU)
 ******************************************************************************/

/**
 * Retrieves the OCSP response stapled to the handshake in ssl, and checks to 
 * see if the returned response is valid.
 * @param ssl The TLS connection to retrieve the stapled response from (a 
 * handshake must be performed before calling this function).
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the stapled response was verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was verified and it contained 
 * the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status OR if no response was stapled.
 */
int check_stapled_response(socket_ctx* sock_ctx) {

    SSL* ssl = sock_ctx->ssl;
	unsigned char* stapled_resp;
	int resp_len, ret;

	resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &stapled_resp);
	if (resp_len < 0)
		return V_OCSP_CERTSTATUS_UNKNOWN;

    ret = check_ocsp_response(stapled_resp, resp_len, sock_ctx);

	return ret;
}


/**
 * Checks the given OCSP response to ensure it is not malformed or invalid, 
 * and then caches the response and returns its status.
 * @param resp_bytes An OCSP response in binary format.
 * @param resp_len The length of resp_bytes.
 * @param sock_ctx The connection to check the response for.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status.
 */
int check_ocsp_response(unsigned char* resp_bytes,
		 int resp_len, socket_ctx* sock_ctx) {

	OCSP_BASICRESP* basicresp = NULL;
	SSL* ssl = sock_ctx->ssl;
	STACK_OF(X509)* chain = NULL;
	X509_STORE* store = NULL;
	OCSP_CERTID* id = NULL;
	int status, ret;

	chain = SSL_get_peer_cert_chain(ssl);
	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
	if (chain == NULL || store == NULL)
		goto err;

	ret = get_ocsp_basicresp(resp_bytes, resp_len, &basicresp);
	if (ret != 0)
		goto err;

	id = get_ocsp_certid(ssl);
	if (id == NULL)
		goto err;

	status = verify_ocsp_basicresp(basicresp, id, chain, store);
	if (status == V_OCSP_CERTSTATUS_UNKNOWN)
		goto err;

    /* even if a user doesn't check cached responses, we shoul add them */
	add_to_ocsp_cache(id, basicresp, sock_ctx->daemon);

	OCSP_CERTID_free(id);

	return status;
 err:
	// Something went wrong with parsing/verification
	if (basicresp != NULL)
		OCSP_BASICRESP_free(basicresp);
	if (id != NULL)
		OCSP_CERTID_free(id);
	
	return V_OCSP_CERTSTATUS_UNKNOWN;
}



/**
 * Verifies the correctness of the signature and timestamps present in 
 * response and checks to make sure it matches the certificate found 
 * in ssl. The OCSP response status found in response is then returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param ssl The TLS connection to verify the response on.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status.
 */
int verify_ocsp_basicresp(OCSP_BASICRESP* resp, 
		OCSP_CERTID* id, STACK_OF(X509)* certs, X509_STORE* store) {
	
	ASN1_GENERALIZEDTIME* revtime = NULL;
	ASN1_GENERALIZEDTIME* thisupd = NULL;
	ASN1_GENERALIZEDTIME* nextupd = NULL;
	int ret, status, reason;

    ret = OCSP_basic_verify(resp, certs, store, 0);
    if (ret != 1)
		return V_OCSP_CERTSTATUS_UNKNOWN;


    ret = OCSP_resp_find_status(resp, id, 
			&status, &reason, &revtime, &thisupd, &nextupd);
    if (ret != 1)
		return V_OCSP_CERTSTATUS_UNKNOWN;


    ret = OCSP_check_validity(thisupd, nextupd, LEEWAY_90_SECS, MAX_OCSP_AGE);
    if (ret != 1) {
        /* response too old */
        log_printf(LOG_ERROR, "cert is too old or has invalid timestamps\n");
        status = V_OCSP_CERTSTATUS_UNKNOWN;
    }

	return status;
}

/*******************************************************************************
 *                   FUNCTIONS TO DO WITH OCSP CACHING
 ******************************************************************************/


int check_cached_response(socket_ctx* sock_ctx) {

	hsmap_t* rev_cache = sock_ctx->daemon->revocation_cache;
	OCSP_BASICRESP* cached_resp = NULL;
	STACK_OF(X509)* chain = NULL;
	X509_STORE* store = NULL;
	OCSP_CERTID* id = NULL;
	char* id_string = NULL;
	int ret;

	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(sock_ctx->ssl));
	chain = SSL_get_peer_cert_chain(sock_ctx->ssl);
	if (store == NULL || chain == NULL)
		goto err;

	id = get_ocsp_certid(sock_ctx->ssl);
	if (id == NULL)
		goto err;

	id_string = get_ocsp_id_string(id);
	if (id_string == NULL)
		goto err;

	cached_resp = (OCSP_BASICRESP*) str_hashmap_get(rev_cache, id_string);
	if (cached_resp == NULL)
		goto err;

	ret = verify_ocsp_basicresp(cached_resp, id, chain, store);
	if (ret == V_OCSP_CERTSTATUS_UNKNOWN) {
		str_hashmap_del(rev_cache, id_string);
		goto err;
	}

	OCSP_CERTID_free(id);
	free(id_string);
	return ret;
 err:
	if (id != NULL)
		OCSP_CERTID_free(id);
	if (id_string != NULL)
		free(id_string);

	return V_OCSP_CERTSTATUS_UNKNOWN;
}


/**
 * Parses the hexadecimal ID of a given OCSP_CERTID.
 * @param certid The OCSP_CERTID to parse an ID from.
 * @returns An ASCII representation of the hexadecimal ID of certid.
 */
char* get_ocsp_id_string(OCSP_CERTID* certid) {

	ASN1_INTEGER* id_int = NULL;
	BIGNUM* id_bignum = NULL;
	char* id_string = NULL;
	char* tmp = NULL;

	OCSP_id_get0_info(NULL, NULL, NULL, &id_int, certid);
	if (id_int == NULL)
		goto err;

	id_bignum = ASN1_INTEGER_to_BN(id_int, NULL);
	if (id_bignum == NULL)
		goto err;

	tmp = BN_bn2hex(id_bignum);
	if (tmp == NULL)
		goto err;

	id_string = strdup(tmp);

	OPENSSL_free(tmp); //so that we don't have to free this way later
	BN_free(id_bignum);

	return id_string;
 err:
	if (id_bignum != NULL)
		BN_free(id_bignum);

	return NULL;
}


/**
 * Adds the given OCSP response to the revocation cache of the daemon.
 * @param response The response to add to the cache
 */
int add_to_ocsp_cache(OCSP_CERTID* id, 
		OCSP_BASICRESP* response, daemon_ctx* daemon) {

	hsmap_t* rev_cache = daemon->revocation_cache;
	char* id_string = NULL;
	int ret;

	id_string = get_ocsp_id_string(id);
	if (id_string == NULL)
		return -1;
	
	ret = str_hashmap_add(rev_cache, id_string, (void*)response);
	if (ret != 0) {
		log_printf(LOG_INFO, "Cache entry already exists\n");
        OCSP_BASICRESP_free(response);
		free(id_string);
		return -1;
	}

	return 0;
}


/*******************************************************************************
 *              HELPER FUNCTIONS FOR HTTP REQUESTS/RESPONSES
 ******************************************************************************/


/**
 * Takes in a given URL and parses it into its hostname, port and path.
 * If no port is specified and the protocol is `http`, then the port specified 
 * will default to 80. Each output may be set to NULL safely (if only some
 * of the outputs are desired).
 * @param url The given url to parse.
 * @param host_out An address to populate with the hostname of the url.
 * @param port_out An address to populate with the port of the url.
 * @param path_out An address to populate with the path of the url.
 * @returns 0 if the url could be successfully parsed, or -1 otherwise.
 */
int parse_url(char* url, char** host_out, int* port_out, char** path_out) {

	char* host;
	char* port_ptr;
	char* path;
	int ret, use_ssl;
    long port;

	ret = OCSP_parse_url(url, &host, &port_ptr, &path, &use_ssl);
	if (ret != 1)
		return -1;

    port = strtol(port_ptr, NULL, 10);
    if (port == INT_MAX || port < 0) {
        free(host);
        free(port_ptr);
        free(path);
        return -1;
    }

    free(port_ptr);

	if (host_out != NULL)
		*host_out = host;
	else
		free(host);
	
	if (port_out != NULL)
		*port_out = (int) port;


	if (path_out != NULL)
		*path_out = path;
	else
		free(path);

	return 0;
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