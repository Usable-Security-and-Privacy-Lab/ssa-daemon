/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SSA_CRL_H
#define SSA_CRL_H

#include "daemon_structs.h"

#define MAX_CRL_RESPONDERS 10
#define OCSP_READ_TIMEOUT 8
#define MAX_HEADER_SIZE 8192
#define LEEWAY_90_SECS 90
#define MAX_CRL_AGE 604800L
#define BUF_LEN sizeof(struct inotify_event) + NAME_MAX + 1


/**
 * Initiates clients to connect to the given CRL responder URLs and retreive
 * Certificate Revocation Lists (CRLs) from them.
 * @param sock_ctx The socket context that the checks are being performed
 * on behalf of.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 */
int launch_crl_checks(revocation_ctx* rev_ctx, int cert_index);


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
int check_crl_response(X509_CRL* crl, X509* subject, X509* issuer, int* response);


/**
 * Parses the CRL_DISTRIBUTION_POINTS field out of a given X.509 certificate
 * and returns a list of URLs designating the location of the distribution 
 * points.
 * @param cert The X.509 certificate to parse distribution points out of.
 * @param num_urls The number of URLs returned.
 * @returns An allocated array of NULL-terminated strings containing the CRL
 * responder URLs.
 */
char** retrieve_crl_urls(X509* cert, int* num_urls);

void cdp_free(char** urls, int num_urls);

int check_crl_cache(hcmap_t* cache_map, X509* cert);

int send_crl_request(struct bufferevent* bev, char* url, char* http_req);

int crl_cache_update(hcmap_t* cache_map, X509_CRL* crl, char* url, 
			char* hostname, sem_t* cache_sem);

int read_crl_cache(hcmap_t* cache_map, FILE* cache_ptr);

int crl_in_cache(hcmap_t* cache_map, char* url);

char* alloc_dup(char* serial, int len);


#endif
