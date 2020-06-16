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




void do_revocation_checks(socket_ctx *sock_ctx);

void pass_revocation_checks(socket_ctx *sock_ctx);
void fail_revocation_checks(socket_ctx* sock_ctx);

int parse_url(char* url, char** host_out, int* port_out, char** path_out);
int is_bad_http_response(char* response);
int get_http_body_len(char* response);
int start_reading_body(responder_ctx* resp_ctx);
int done_reading_body(responder_ctx* resp_ctx);


/* stapled response checks */
int check_ocsp_response(unsigned char* resp_bytes,
		 int resp_len, socket_ctx* sock_ctx);
int verify_ocsp_basicresp(OCSP_BASICRESP* resp, 
		OCSP_CERTID* id, STACK_OF(X509)* certs, X509_STORE* store);

/* ocsp cache functions */
int check_cached_response(socket_ctx* sock_ctx);

char* get_ocsp_id_string(OCSP_CERTID* certid);
int add_to_ocsp_cache(OCSP_CERTID* id, 
		OCSP_BASICRESP* response, daemon_ctx* daemon);

#endif