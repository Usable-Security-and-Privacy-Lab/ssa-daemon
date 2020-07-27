#include <openssl/ssl.h>

#include "crl.h"

/**
 * Parses the CRL_DISTRIBUTION_POINTS field out of a given X.509 certificate
 * and returns a list of URLs designating the location of the distribution 
 * points.
 * @param cert The X.509 certificate to parse distribution points out of.
 * @param num_urls The number of URLs returned.
 * @returns An allocated array of NULL-terminated strings containing the CRL
 * responder URLs.
 */
char** retrieve_crl_urls(X509* cert, int* num_urls) {

    return NULL; //TODO: stub
}




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


/**
 * Verifies the correctness of the signature and timestamps present in the 
 * given CRL list and checks to see if it contains an entry for the certificate 
 * found in ssl. If so, the CRL revoked status is returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param ssl The TLS connection to verify the response on.
 * @returns 1 if a revoked status was found for the certificate in the CRL, or
 * 0 if no such status was found; or -1 if the response's correctness could not 
 * be verified.
 */
int do_crl_response_checks(X509_CRL* response, SSL* ssl) {

    return -1; //TODO: stub
}