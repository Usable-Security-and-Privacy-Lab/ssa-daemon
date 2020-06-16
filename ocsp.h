#ifndef SSA_OCSP_H
#define SSA_OCSP_H

#include <openssl/ocsp.h>

#include "daemon_structs.h"


#define MAX_OCSP_RESPONDERS 5
#define OCSP_READ_TIMEOUT 8


char** retrieve_ocsp_urls(X509* cert, int* num_urls);
void launch_ocsp_checks(socket_ctx* sock_ctx, char** urls, int num_urls);

int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp);
OCSP_CERTID* get_ocsp_certid(SSL* ssl);













#endif