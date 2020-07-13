#ifndef SSA_CRL_H
#define SSA_CRL_H

#include "daemon_structs.h"

int launch_crl_checks(socket_ctx* sock_ctx, char** urls, int num_urls);

int do_crl_response_checks(X509_CRL* response, SSL* ssl);

char** retrieve_crl_urls(X509* cert, int* num_urls);



#endif