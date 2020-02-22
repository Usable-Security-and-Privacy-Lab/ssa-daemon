#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "config.h"
#include "log.h"
#include "tls_client.h"
#include "tls_common.h"


SSL_CTX* client_settings_init(char* path) {
    SSL_CTX *client_settings;
	/*
	ssa_config_t* ssa_config;
	char* store_file;
	*/
	client_settings = SSL_CTX_new(TLS_client_method());
	if (client_settings == NULL)
		goto err_ctx;
	
	/* TODO: use this code??
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
		*/ /*
		store_file = ssa_config->trust_store;
		log_printf(LOG_INFO, "Setting cert root store to %s\n", store_file);
		if (SSL_CTX_load_verify_locations(client_settings, store_file, store_file) == 0) {
			log_printf(LOG_ERROR, "Unable set truststore %s\n",ssa_config->trust_store);
		}
	} else {
		
		log_printf(LOG_INFO, "Unable to find ssa configuration\n");
		*/
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
	/*
	}
	*/

	return client_settings;
err:
	SSL_CTX_free(client_settings);
err_ctx:
	log_printf(LOG_ERROR, "Initiating tls client settings failed.\n");
	return NULL;
}

connection* client_connection_new(daemon_context* daemon) {
	connection* client_conn;

	client_conn = (connection*)calloc(1, sizeof(connection));
	if (client_conn == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate connection: %s\n", strerror(errno));
		goto err;
	}

	client_conn->tls = SSL_new(daemon->client_settings);
	if (client_conn->tls == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate SSL object.\n");
		goto err;
	}
	client_conn->daemon = daemon;

	return client_conn;
err:
	/* TODO: make connection_free(); */
	return NULL;
}

int client_connection_setup(connection* client_conn, daemon_context* daemon_ctx, char* hostname, evutil_socket_t efd, int is_accepting) {
	
	if (hostname != NULL) {
		SSL_set_tlsext_host_name(client_conn->tls, hostname);
	}

	/* socket set to -1 because we set it later */
	client_conn->plain.bev = bufferevent_socket_new(daemon_ctx->ev_base, -1,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	//ctx->plain.connected = 1;
	if (client_conn->plain.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [direct mode]\n");
		/* Need to close socket because it won't be closed on free since bev creation failed */
		connection_free(client_conn);
		return 0;
	}

	/* TODO: Take this out soon. */
	if (is_accepting == 1) { /* TLS server role */
		client_conn->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, client_conn->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}
	else { /* TLS client role */
		client_conn->secure.bev = bufferevent_openssl_socket_new(daemon_ctx->ev_base, efd, client_conn->tls,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	if (client_conn->secure.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [direct mode]\n");
		connection_free(client_conn);
		return 0;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */


	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(client_conn->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, client_conn);
	bufferevent_enable(client_conn->secure.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(client_conn->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, client_conn);

	return 1;
}
