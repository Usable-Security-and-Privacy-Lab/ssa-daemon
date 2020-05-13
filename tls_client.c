#include <errno.h>
#include <string.h>

#include <unistd.h> //added to use the access function call.

#include <openssl/ssl.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "daemon_structs.h"
#include "bev_callbacks.h"


SSL_CTX* client_settings_init(char* path) {
	char* CA_file;
	if(access("/etc/pki/tls/certs/ca-bundle.crt", F_OK) != -1) { //FEDORA
		log_printf(LOG_INFO, "Found the fedora CA file.\n");
		CA_file = (char*)malloc((strlen("/etc/pki/tls/certs/ca-bundle.crt") + 1) * sizeof(char));
		strcpy(CA_file, "/etc/pki/tls/certs/ca-bundle.crt");
		//CA_file = "/etc/pki/tls/certs/ca-bundle.crt";
	}
	else if (access("/etc/ssl/certs/ca-certificates.crt", F_OK) != -1) { //UBUNTU
		log_printf(LOG_INFO, "Found the ubuntu CA file.\n");
		CA_file = (char*)malloc((strlen("/etc/ssl/certs/ca-certificates.crt") + 1) * sizeof(char));
		strcpy(CA_file, "/etc/ssl/certs/ca-certificates.crt");
		//CA_file = "/etc/ssl/certs/ca-certificates.crt";
	}
	else { //UNSUPPORTED OS
		log_printf(LOG_ERROR, "Unable to find valid cert location.\n");
		goto err_ctx;
	}
  
	SSL_CTX *client_settings = SSL_CTX_new(TLS_client_method());
	if (client_settings == NULL)
		goto err_ctx;

	/* TODO: eventually move these things to a config file */
	const char* test_CA_file = "test_files/certs/rootCA.pem";
	//const char* CA_file = "/etc/pki/tls/certs/ca-bundle.crt"; //FEDORA
	//const char* CA_file = "/etc/ssl/certs/ca-certificates.crt"; //UBUNTU

	
	const char* cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
	                          "ECDHE-RSA-AES256-GCM-SHA384:"
							  "ECDHE-ECDSA-CHACHA20-POLY1305:"
							  "ECDHE-RSA-CHACHA20-POLY1305:"
							  "ECDHE-ECDSA-AES128-GCM-SHA256:"
							  "ECDHE-RSA-AES128-GCM-SHA256";

	const char *ciphersuites = "TLS_AES_256_GCM_SHA384:"
                               "TLS_AES_128_GCM_SHA256:"
							   "TLS_CHACHA20_POLY1305_SHA256:"
							   "TLS_AES_128_CCM_SHA256:"
							   "TLS_AES_128_CCM_8_SHA256";

	SSL_CTX_set_verify(client_settings, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_options(client_settings, SSL_OP_NO_COMPRESSION 
			| SSL_OP_NO_TICKET);


	if (SSL_CTX_set_min_proto_version(client_settings, TLS1_2_VERSION) != 1) {
		goto err;
	}
	if (SSL_CTX_set_max_proto_version(client_settings, TLS_MAX_VERSION) != 1) {
		goto err;
	}
	if (SSL_CTX_set_ciphersuites(client_settings, ciphersuites) != 1) {
		goto err;
	}
	if (SSL_CTX_set_cipher_list(client_settings, cipher_list) != 1) {
		goto err;
	}
	if (SSL_CTX_load_verify_locations(client_settings, CA_file, NULL) != 1) {
		goto err;
	}

	free(CA_file);

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
	log_printf(LOG_ERROR, "OpenSSL error initializing client SSL_CTX: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	return NULL;
}

/**
 * Attempts to create a new SSL struct and attach it to the given connection.
 * If unsuccessful, the connection's state will not be altered--if it
 * contained an SSL struct prior to this call, that struct will remain.
 * @param conn The connection to assign a new client SSL struct to.
 * @returns 0 on success; -errno otherwise.
 */
int client_SSL_new(connection* conn, daemon_context* daemon) {

	SSL* new_ssl = SSL_new(daemon->client_settings);
	if (new_ssl == NULL)
		return ssl_malloc_err(conn);

	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = new_ssl;

	return 0;
}

/**
 * Prepares a client connection by creating/configuring bufferevents and
 * setting hostname validation.
 *
 * @param sock_ctx The socket context of the connection to be set up.
 * @returns 0 on success; -errno on failure. In the event of a failure, it is
 * left to the calling function to clean up sock_ctx and set its error state.
 */
int client_connection_setup(sock_context* sock_ctx) {

	daemon_context* daemon = sock_ctx->daemon;
	connection* conn = sock_ctx->conn;
	char* hostname = sock_ctx->rem_hostname;
	int ret;

	if (hostname != NULL) {
		log_printf(LOG_INFO, "Hostname passed in is: %s\n", hostname);
		SSL_set_tlsext_host_name(conn->tls, hostname);
		ret = SSL_set1_host(conn->tls, hostname);
		if (ret != 1) {
			ret = -ECONNABORTED; /* TODO: set SSL error here */
			goto err;
		}
	}

	/* socket set to -1 because we set it later */
	conn->plain.bev = bufferevent_socket_new(daemon->ev_base,
			NOT_CONN_BEV, BEV_OPT_CLOSE_ON_FREE);
	if (conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		goto err;
	}

	conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base,
			sock_ctx->fd, conn->tls, BUFFEREVENT_SSL_CONNECTING, 0);
	if (conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		goto err;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL */
	bufferevent_openssl_set_allow_dirty_shutdown(conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(conn->secure.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);
	bufferevent_setcb(conn->plain.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);

	struct timeval read_timeout = {
			.tv_sec = EXT_CONN_TIMEOUT,
			.tv_usec = 0,
	};

	ret = bufferevent_set_timeouts(conn->secure.bev, &read_timeout, NULL);
	if (ret < 0) {
		ret = -ECONNABORTED;
		goto err;
	}

	ret = bufferevent_enable(conn->secure.bev, EV_READ | EV_WRITE);
	if (ret < 0) {
		ret = -ECONNABORTED;
		goto err;
	}

	return 0;
 err:
	log_printf(LOG_ERROR, "Failed to set up client/server bev [direct mode]\n");
	/* NOTE: intentionally left to the calling function to clean up errors */
	return ret;
}
