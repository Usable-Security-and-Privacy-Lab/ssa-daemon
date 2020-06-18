#ifndef SSA_REVOCATION_H
#define SSA_REVOCATION_H

#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "daemon_structs.h"



#define LEEWAY_90_SECS 90
#define MAX_OCSP_AGE 604800L /* 7 days is pretty standard for OCSP */



void set_revocation_state(socket_ctx* sock_ctx, enum revocation_state state);

OCSP_CERTID* get_ocsp_certid(SSL* ssl);

int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp);



char** retrieve_ocsp_urls(X509* cert, int* num_urls);

char** retrieve_crl_urls(X509* cert, int* num_urls);

int parse_url(char* url, char** host_out, int* port_out, char** path_out);



int check_stapled_response(socket_ctx* sock_ctx);

int verify_ocsp_basicresp(OCSP_BASICRESP* resp, 
		OCSP_CERTID* id, STACK_OF(X509)* certs, X509_STORE* store);

int do_ocsp_response_checks(unsigned char* resp_bytes,
		 int resp_len, socket_ctx* sock_ctx);

int do_crl_response_checks(X509_CRL* response, SSL* ssl);



char* get_ocsp_id_string(OCSP_CERTID* certid);

int add_to_ocsp_cache(OCSP_CERTID* id, 
		OCSP_BASICRESP* response, daemon_ctx* daemon);

int check_cached_response(socket_ctx* sock_ctx);

#endif