
#include "openssl/ssl.h"

#include "config.h"
#include "log.h"
#include "tls_client.h"


SSL_CTX* client_settings_init(char* path) {
    SSL_CTX *client_settings;
	ssa_config_t* ssa_config;
	char* store_file;

	client_settings = SSL_CTX_new(TLS_client_method());
	if (client_settings == NULL)
		goto err_ctx;
	
	ssa_config = get_app_config(path);
	if (ssa_config) {
		log_printf(LOG_INFO, "MinVersion: %d\n", ssa_config->min_version);
		if (SSL_CTX_set_min_proto_version(client_settings, ssa_config->min_version) == 0) {
			log_printf(LOG_ERROR, "Unable to set min protocol version for %s\n",path);
		}
		if (SSL_CTX_set_max_proto_version(client_settings, ssa_config->max_version) == 0) {
			log_printf(LOG_ERROR, "Unable to set max protocol version for %s\n",path);
		}
		if (SSL_CTX_set_cipher_list(client_settings, ssa_config->cipher_list) == 0) {
			log_printf(LOG_ERROR, "Unable to set cipher list for %s\n",path);
		}
		/* TODO: We don't support store yet (should we??)
		stat(ssa_config->trust_store, &stat_store);
		if (S_ISDIR(stat_store.st_mode)) {
			store_dir = ssa_config->trust_store;
		} else {
		*/
		store_file = ssa_config->trust_store;
		log_printf(LOG_INFO, "Setting cert root store to %s\n", store_file);
		if (SSL_CTX_load_verify_locations(client_settings, store_file, store_file) == 0) {
			log_printf(LOG_ERROR, "Unable set truststore %s\n",ssa_config->trust_store);
		}
	} else {
		log_printf(LOG_INFO, "Unable to find ssa configuration\n");

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
	}

	return client_settings;
err:
	SSL_CTX_free(client_settings);
err_ctx:
	log_printf(LOG_ERROR, "Initiating tls client settings failed.\n");
	return NULL;
}