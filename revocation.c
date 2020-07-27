#include <string.h>

#include <event2/bufferevent.h>

#include "crl.h"
#include "error.h"
#include "hashmap.h"
#include "log.h"
#include "netlink.h"
#include "ocsp.h"
#include "revocation.h"


int begin_revocation_checks(revocation_ctx *rev_ctx, SSL* ssl, int cert_index);
int check_cached_response(revocation_ctx* rev_ctx, OCSP_CERTID* id);
int check_stapled_response(revocation_ctx* rev_ctx, SSL* ssl, OCSP_CERTID* id);

/**
 * Begins revocation checks on the given socket's peer. The socket must have 
 * a TLS handshake completed with the peer before such checks can be performed.
 * This function will begin checks on certificate within the peer's certificate
 * chain except for the root CA.
 * @param sock_ctx The context of the socket to start revocation checks for.
 */
void do_cert_chain_revocation_checks(socket_ctx* sock_ctx) {

    revocation_ctx* rev_ctx = &sock_ctx->rev_ctx;
    int ret;

    ret = revocation_context_setup(rev_ctx, sock_ctx);
    if (ret != 0)
        goto err;

    for (int i = 0; i < rev_ctx->total_to_check; i++) {
        ret = begin_revocation_checks(rev_ctx, sock_ctx->ssl, i);
        if (ret != 0)
            goto err;
    }

    if (rev_ctx->left_to_check == 0)
        pass_revocation_checks(rev_ctx);

    return;
err:
    if (ret == -2)
        set_err_string(sock_ctx, "TLS handshake error: "
                "certificate was revoked");
    else 
        set_err_string(sock_ctx, "TLS handshake error: "
                "one or more of the peer's certificates in its certificate "
                "chain could not be checked for revocation");

    fail_revocation_checks(rev_ctx);
}

/**
 * Checks the certificate in the peer's certificate chain at the given index for
 * its revocation status, and launches clients if needed to get its status from
 * OCSP/CRL responders.
 * @param rev_ctx The context of the connection to do revocation checks for.
 * @param ssl The ssl object of the given connection.
 * @param cert_index The index of the certificate to do revocation checks. Note
 * that the root certificate should never be checked.
 * @returns 0 if checks were successfully performed or launched, -1 if checks 
 * could not be performed for the certificate at the given index, or -2 if the
 * given certificate is revoked.
 */
int begin_revocation_checks(revocation_ctx *rev_ctx, SSL* ssl, int cert_index) {

    OCSP_CERTID* id;
    int ret;
    
    id = get_ocsp_certid(rev_ctx, cert_index);
    if (id == NULL)
        goto err;

    if (has_cached_checks(rev_ctx->checks)) {

        ret = check_cached_response(rev_ctx, id);
        if (ret == V_OCSP_CERTSTATUS_GOOD) {
            /*
            log_printf(LOG_INFO, "Cached ocsp response good!\n");
            */
            rev_ctx->left_to_check -= 1;

            OCSP_CERTID_free(id);
            return 0;

        } else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
            OCSP_CERTID_free(id);
            return -2;
        }
    }

    if (has_stapled_checks(rev_ctx->checks)) {
        
        ret = check_stapled_response(rev_ctx, ssl, id);
        if (ret == V_OCSP_CERTSTATUS_GOOD) {
            /*
            log_printf(LOG_INFO, "Stapled ocsp response good!\n");
            */
            rev_ctx->left_to_check -= 1;

            OCSP_CERTID_free(id);
            return 0;

        } else if (ret == V_OCSP_CERTSTATUS_REVOKED) {
            OCSP_CERTID_free(id);
            return -2;
        }
    }

    if (has_ocsp_checks(rev_ctx->checks)) {
        ret = launch_ocsp_checks(rev_ctx, cert_index, id);
        rev_ctx->responders_at[cert_index] = ret;
    }
        
    /*
    if (has_crl_checks(rev_ctx->checks))
        crl_urls = retrieve_crl_urls(subject, &crl_url_cnt);

    if (crl_url_cnt > 0) {
        ret = launch_crl_checks(rev_ctx, crl_urls, crl_url_cnt);
        rev_ctx->crl_responders_at[cert_index] = ret;
        if (ret > 0)
            rev_ctx->responders_at[cert_index] += 1;
    }

    */

    if (rev_ctx->responders_at[cert_index] == 0)
        goto err;

    OCSP_CERTID_free(id);
    return 0;
err:
    if (id != NULL)
        OCSP_CERTID_free(id);
    return -1;
}

/**
 * Designates a given certificate being queried for by a responder as valid and 
 * unrevoked, and cancels all other bufferevents querying responders for the 
 * same certificate. If no more certificates are left to be checked, this 
 * function will also pass the revocation checks and report handshake success
 * to the kernel over netlink.
 * @param ocsp_resp The ocsp responder that successfully verified its given
 * certificate.
 */
void pass_individual_rev_check(ocsp_responder* ocsp_resp) {

    revocation_ctx* rev_ctx = ocsp_resp->rev_ctx;

    ocsp_responder* curr = rev_ctx->ocsp_responders;
    while (curr != NULL) {
        if (curr->cert_position == ocsp_resp->cert_position)
            ocsp_responder_shutdown(curr);
            /* TODO: actually take out the node from the linked list */
        
        curr = curr->next;
    }

    rev_ctx->left_to_check -= 1;

    if (rev_ctx->left_to_check == 0)
        pass_revocation_checks(rev_ctx);

}

/**
 * Reports handshake success to the kernel over netlink, and shuts down any 
 * bufferevents still performing revocation checks.
 * @param rev_ctx The revocation context of the socket.
 */
void pass_revocation_checks(revocation_ctx *rev_ctx) {

    netlink_handshake_notify_kernel(rev_ctx->daemon, rev_ctx->id, NOTIFY_SUCCESS);
    revocation_context_cleanup(rev_ctx);
}


/**
 * Stops any pending revocation checks, sets the socket associated with the 
 * revocation checks to an error state and notifies the kernel that the 
 * handshake failed. This function can safely be called at any point in the
 * revocation process, as long as it is not called twice in the same callback
 * or function path (the kernel SHOULD NOT be notified twice--it causes bugs).
 * @param rev_ctx The revocation context associated with the connection to be
 * failed.
 */
void fail_revocation_checks(revocation_ctx* rev_ctx) {

    daemon_ctx *daemon = rev_ctx->daemon;
    unsigned long id = rev_ctx->id;
    socket_ctx *sock_ctx = rev_ctx->sock_ctx;

    socket_shutdown(sock_ctx);
    sock_ctx->state = SOCKET_ERROR;

    netlink_handshake_notify_kernel(daemon, id, -EPROTO);
    revocation_context_cleanup(rev_ctx);

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
int check_stapled_response(revocation_ctx* rev_ctx, SSL* ssl, OCSP_CERTID* id) {

    unsigned char* stapled_resp;
    int resp_len, ret;

    resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &stapled_resp);
    if (resp_len < 0)
        return V_OCSP_CERTSTATUS_UNKNOWN;

    ret = check_ocsp_response(stapled_resp, resp_len, rev_ctx, id);

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
            int resp_len, revocation_ctx* rev_ctx, OCSP_CERTID* id) {

    OCSP_BASICRESP* basicresp = NULL;
    int status, ret;

    ret = get_ocsp_basicresp(resp_bytes, resp_len, &basicresp);
    if (ret != 0)
        goto err;

    status = verify_ocsp_basicresp(basicresp, 
                id, rev_ctx->certs, rev_ctx->store);
    if (status == V_OCSP_CERTSTATUS_UNKNOWN)
        goto err;

    /* even if a user doesn't check cached responses, we should add them */
    add_to_ocsp_cache(id, basicresp, rev_ctx->daemon);

    return status;
err:
    // Something went wrong with parsing/verification
    if (basicresp != NULL)
        OCSP_BASICRESP_free(basicresp);
    
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

/**
 * Checks for a cached response containing the given id, and verifies/returns 
 * its status if one exists. If the cached response is too old, it will be 
 * removed from the cache and this function will return 
 * V_OCSP_CERTSTATUS_UNKNOWN. 
 * @param rev_ctx The revocation context of the connection to obtain a cached
 * response for.
 * @param id The ID of the certificate we want to get a revocation status for.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the given ID did not have an entry in the
 * cache, OR if the entry in the cache was no longer valid.
 */
int check_cached_response(revocation_ctx* rev_ctx, OCSP_CERTID* id) {

    hsmap_t* rev_cache = rev_ctx->daemon->revocation_cache;
    OCSP_BASICRESP* response = NULL;
    char* id_string = NULL;
    int status;

    id_string = get_ocsp_id_string(id);
    if (id_string == NULL)
        goto err;

    response = (OCSP_BASICRESP*) str_hashmap_get(rev_cache, id_string);
    if (response == NULL)
        goto err;

    status = verify_ocsp_basicresp(response, id, rev_ctx->certs, rev_ctx->store);
    if (status == V_OCSP_CERTSTATUS_UNKNOWN) {
        str_hashmap_del(rev_cache, id_string);
        goto err;
    }

    free(id_string);

    return status;
err:
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
 * @param id The id of the response (to use as the key in the hashmap).
 * @param response The response to add to the cache
 * @param daemon The daemon's context (which contains the cache hashmap).
 * @returns 0 on success, or -1 if the response could not be cached/the
 * cached entry already exists.
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
int start_reading_body(ocsp_responder* ocsp_resp) {

    unsigned char* body_start;
    int header_len;
    int body_len;

    if (is_bad_http_response((char*) ocsp_resp->buffer))
        return -1;

    body_start = (unsigned char*) strstr((char*) ocsp_resp->buffer, "\r\n\r\n") 
            + strlen("\r\n\r\n");
    header_len = body_start - ocsp_resp->buffer;

    body_len = get_http_body_len((char*) ocsp_resp->buffer);
    if (body_len < 0)
        return -1;

    unsigned char* tmp_buffer = (unsigned char*) malloc(body_len);
    if (tmp_buffer == NULL)
        return -1;

    ocsp_resp->tot_read -= header_len;
    ocsp_resp->buf_size = body_len;

    memcpy(tmp_buffer, body_start, ocsp_resp->tot_read);
    free(ocsp_resp->buffer);
    ocsp_resp->buffer = tmp_buffer;

    ocsp_resp->is_reading_body = 1;

    return 0;
}


/**
 * Determines whether the given ocsp responder has finished reading all of
 * the data it needs to.
 * @param resp_ctx The ocsp responder to check.
 * @returns 1 if done, 0 if not done.
 */
int done_reading_body(ocsp_responder* resp_ctx) {
    return resp_ctx->is_reading_body 
                && (resp_ctx->tot_read == resp_ctx->buf_size);
}