#include <errno.h>
#include <string.h>

#include <unistd.h> //added to use the access function call.

#include <openssl/ssl.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "config.h"
#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "daemon_structs.h"
#include "bev_callbacks.h"


#define DEFAULT_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:"  \
							"ECDHE-RSA-AES256-GCM-SHA384:"    \
							"ECDHE-ECDSA-CHACHA20-POLY1305:"  \
							"ECDHE-RSA-CHACHA20-POLY1305:"    \
							"ECDHE-ECDSA-AES128-GCM-SHA256:"  \
							"ECDHE-RSA-AES128-GCM-SHA256"

#define DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:"       \
                             "TLS_AES_128_GCM_SHA256:"       \
							 "TLS_CHACHA20_POLY1305_SHA256:" \
							 "TLS_AES_128_CCM_SHA256:"       \
							 "TLS_AES_128_CCM_8_SHA256"



SSL_CTX* client_ctx_init_default();



/**
 * Allocates a new SSL_CTX struct and loads the settings found in config into
 * it. If config is NULL, then secure default settings are loaded using
 * client_ctx_init_default().
 * @param config The configuration settings to have applied to the given
 * client SSL_CTX.
 * @returns A pointer to a newly allocated and set SSL_CTX, or NULL on error.
 */
SSL_CTX* client_ctx_init(client_settings* config) {

	SSL_CTX* ctx = NULL;
	long tls_version;
	int ret;

	if (config == NULL)
		return client_ctx_init_default();

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		goto err;


	SSL_CTX_set_security_level(ctx, 0);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);


	if (!config->tls_compression)
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	tls_version = get_tls_version(config->min_tls_version);
	if (SSL_CTX_set_min_proto_version(ctx, tls_version) != 1) 
		goto err;

	tls_version = get_tls_version(config->max_tls_version);
	if (SSL_CTX_set_max_proto_version(ctx, tls_version) != 1)
		goto err;


	if (config->cipher_list_cnt > 0) {
		ret = load_cipher_list(ctx, 
				config->cipher_list, config->cipher_list_cnt);
	} else {
		ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	}
	if (ret != 1)
		goto err;
	

	if (config->ciphersuite_cnt > 0) {
		ret = load_ciphersuites(ctx, 
				config->ciphersuites, config->ciphersuite_cnt);
	} else {
		ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	}
	if (ret != 1)
		goto err;

	ret = load_certificate_authority(ctx, config->ca_path);
	if (ret != 1)
		goto err;

	return ctx;
 err:
	if (ERR_peek_error())
		log_printf(LOG_ERROR, "OpenSSL error initializing client SSL_CTX: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	
	if (ctx != NULL)
		SSL_CTX_free(ctx);
    return NULL;
}

/**
 * Creates a new client SSL_CTX with secure default settings applied to it.
 * @returns A pointer to a newly allocated SSL_CTX set with secure settings, or
 * NULL on failure.
 */
SSL_CTX* client_ctx_init_default() {

	int ret;

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		goto err;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION 
			| SSL_OP_NO_TICKET);

	ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_max_proto_version(ctx, TLS_MAX_VERSION);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	if (ret != 1)
		goto err;

	ret = load_certificate_authority(ctx, NULL);
	if (ret != 1)
		goto err;

	return ctx;
 err:
	if (ctx != NULL)
		SSL_CTX_free(ctx);

	if (ERR_peek_error() != 0)
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

	SSL* new_ssl = SSL_new(daemon->client_ctx);
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
