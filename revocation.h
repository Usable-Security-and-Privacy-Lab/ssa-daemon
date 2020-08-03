#ifndef SSA_REVOCATION_H
#define SSA_REVOCATION_H

#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "daemon_structs.h"

#include "ocsp.h"
#include "crl.h"


#define LEEWAY_90_SECS 90
#define MAX_OCSP_AGE 604800L /* 7 days is pretty standard for OCSP */

#define MAX_HEADER_SIZE 8192



/**
 * Begins revocation checks on the given socket's peer. The socket must have 
 * a TLS handshake completed with the peer before such checks can be performed.
 * This function will begin checks on certificate within the peer's certificate
 * chain except for the root CA.
 * @param sock_ctx The context of the socket to start revocation checks for.
 */
void do_cert_chain_revocation_checks(socket_ctx* sock_ctx);


/**
 * Designates a given certificate being queried for by a responder as valid and 
 * unrevoked, and cancels all other bufferevents querying responders for the 
 * same certificate. If no more certificates are left to be checked, this 
 * function will also pass the revocation checks and report handshake success
 * to the kernel over netlink.
 * @param ocsp_resp The ocsp responder that successfully verified its given
 * certificate.
 */
void pass_individual_rev_check(ocsp_responder* ocsp_resp);


/**
 * Designates a given certificate being queried for by a responder as valid and 
 * unrevoked, and cancels all other bufferevents querying responders for the 
 * same certificate. If no more certificates are left to be checked, this 
 * function will also pass the revocation checks and report handshake success
 * to the kernel over netlink.
 * @param crl_resp The crl responder that successfully verified its given
 * certificate.
 */
void pass_individual_crl_check(crl_responder* crl_resp);


/**
 * Reports handshake success to the kernel over netlink, and shuts down any 
 * bufferevents still performing revocation checks.
 * @param rev_ctx The revocation context of the socket.
 */
void pass_revocation_checks(revocation_ctx *rev_ctx);


/**
 * Stops any pending revocation checks, sets the socket associated with the 
 * revocation checks to an error state and notifies the kernel that the 
 * handshake failed. This function can safely be called at any point in the
 * revocation process, as long as it is not called twice in the same callback
 * or function path (the kernel SHOULD NOT be notified twice--it causes bugs).
 * @param rev_ctx The revocation context associated with the connection to be
 * failed.
 */
void fail_revocation_checks(revocation_ctx* rev_ctx);


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
int parse_url(char* url, char** host_out, int* port_out, char** path_out);


/**
 * Checks to see if a given response has a a return code.
 * @param response The response to check the HTTP response code of.
 * @returns 0 if the response contains an HTTP 200 code (OK), or 1 otherwise.
 */
int is_bad_http_response(char* response);


/**
 * Determines the length of an HTTP response's body, based on the Content-Length
 * field in the HTTP header.
 * @param response the HTTP response to parse the response from.
 * @returns The length of the response body, or -1 on error.
 */
int get_http_body_len(char* response);


/**
 * Transitions a given responder's buffer and buffer length to reading an HTTP
 * response body (rather than reading the header + body). This function 
 * re-allocates the buffer within resp_ctx to the correct size for the body and sets
 * the flag in responder indicating that the buffer contains only the response
 * body.
 * @param resp_ctx The given responder to modify the buffer of.
 * @returns 0 on success, or if an error occurred.
 */
int start_reading_body(void* generic_resp);

/**
 * Determines whether the given ocsp responder has finished reading all of
 * the data it needs to.
 * @param resp_ctx The ocsp responder to check.
 * @returns 1 if done, 0 if not done.
 */
int done_reading_body(void* generic_resp);


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
            int resp_len, revocation_ctx* rev_ctx, OCSP_CERTID* id);


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
        OCSP_CERTID* id, STACK_OF(X509)* certs, X509_STORE* store);



/* ocsp cache functions */

/**
 * Parses the hexadecimal ID of a given OCSP_CERTID.
 * @param certid The OCSP_CERTID to parse an ID from.
 * @returns An ASCII representation of the hexadecimal ID of certid.
 */
char* get_ocsp_id_string(OCSP_CERTID* certid);


/**
 * Adds the given OCSP response to the revocation cache of the daemon.
 * @param id The id of the response (to use as the key in the hashmap).
 * @param response The response to add to the cache
 * @param daemon The daemon's context (which contains the cache hashmap).
 * @returns 0 on success, or -1 if the response could not be cached/the
 * cached entry already exists.
 */
int add_to_ocsp_cache(OCSP_CERTID* id, 
        OCSP_BASICRESP* response, daemon_ctx* daemon);

#endif
