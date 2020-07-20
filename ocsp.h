#ifndef SSA_OCSP_H
#define SSA_OCSP_H

#include <openssl/ocsp.h>

#include "daemon_structs.h"


#define MAX_OCSP_RESPONDERS 5
#define OCSP_READ_TIMEOUT 8


/**
 * Parses the AUTHORITY_INFORMATION_ACCESS field out of a given X.509 
 * certificate and returns a list of URLS designating the location of the 
 * OCSP responders.
 * @param cert The X.509 certificate to parse OCSP responder information from.
 * @param num_urls The number of OCSP responder URLs parsed from cert.
 * @returns An allocated array of NULL-terminated strings containing the 
 * URLs of OCSP responders.
 */
char** retrieve_ocsp_urls(X509* cert, int* num_urls);


/**
 * Initiates clients to connect to the given OCSP responder URLs and retrieve
 * OCSP revocation responses from them.
 * @param rev_ctx The revocation context that the checks are being performed in.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 * @returns The number of different responders that were successfully queried.
 */
int launch_ocsp_checks(revocation_ctx* rev_ctx, int cert_index, OCSP_CERTID* id);


/**
 * Converts a given array of bytes into an OCSP_RESPONSE, checks its validity,
 * and extracts the basic response found within the response.
 * @param bytes The given bytes to convert.
 * @param len The length of bytes.
 * @param resp The OCSP basic response structure extracted from bytes.
 * @returns 0 on success, or -1 if an error occurred.
 */
int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp);


/**
 * Creates an OCSP_CERTID for the certificate at the given index in the peer's
 * cert chain.
 * @param rev_ctx The revocation context for the connection (contains the peer's
 * certificate chain).
 * @param cert_index The index of the certificate in the chain to get an 
 * OCSP_CERTID for.
 * @returns A newly allocated OCSP_CERTID, or NULL on failure.
 */
OCSP_CERTID* get_ocsp_certid(revocation_ctx* rev_ctx, int cert_index);













#endif