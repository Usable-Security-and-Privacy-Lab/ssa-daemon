/*
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

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "daemon.h"

SSL_CTX* client_settings_init() {
    SSL_CTX *client_settings;

	client_settings = SSL_CTX_new(TLS_client_method());
	if (client_settings == NULL)
		goto err_ctx;
	
	const char* CA_file = "/etc/pki/tls/certs/ca-bundle.crt";
	const char* cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
	/* const char *ciphersuites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";
	*/
	/* TODO: Uncomment this eventually */
	
	SSL_CTX_set_verify(client_settings, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_options(client_settings, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);

	if (SSL_CTX_set_min_proto_version(client_settings, TLS1_2_VERSION) != 1) 
		goto err;
	if (SSL_CTX_set_max_proto_version(client_settings, TLS_MAX_VERSION) != 1) 
		goto err;
	/* TODO: Get my personal working with OpenSSL 1.1.1 before this will work
	if (SSL_CTX_set_ciphersuites(client_settings, ciphersuites) != 1) 
		goto err;
	*/
	if (SSL_CTX_set_cipher_list(client_settings, cipher_list) != 1) 
		goto err;
	if (SSL_CTX_load_verify_locations(client_settings, CA_file, NULL) != 1)
		goto err;

	/* TODO: Eventually enable OCSP Stapling, CRL checking and OCSP checking
	if (SSL_CTX_set_tlsext_status_type(client_settings, TLSEXT_STATUSTYPE_ocsp) == -1) 
		goto err;
	if (SSL_CTX_set_tlsext_status_cb(client_settings, <put_callback_function_here>) != 1)
		goto err;
	if (SSL_CTX_set_tlsext_status_arg(client_settings, <put_Arg_here>) != 1) 
		goto err;
	*/

	return client_settings;
err:
	SSL_CTX_free(client_settings);
err_ctx:
	log_printf(LOG_ERROR, "Initiating tls client settings failed.\n");
	return NULL;
}








#endif