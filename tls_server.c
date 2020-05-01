#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>

#include "bev_callbacks.h"
#include "daemon_structs.h"
#include "log.h"
#include "tls_server.h"

SSL_CTX* server_settings_init(char* path) {
	const char* cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
							  "ECDHE-RSA-AES256-GCM-SHA384:"
							  "ECDHE-ECDSA-CHACHA20-POLY1305:"
							  "ECDHE-RSA-CHACHA20-POLY1305:"
							  "ECDHE-ECDSA-AES128-GCM-SHA256:"
							  "ECDHE-RSA-AES128-GCM-SHA256";
	SSL_CTX* server_settings = NULL;
	unsigned long ssl_err;

	server_settings = SSL_CTX_new(TLS_server_method());
	if (server_settings == NULL)
		goto err;

	SSL_CTX_set_verify(server_settings, SSL_VERIFY_NONE, NULL);

	if (SSL_CTX_set_min_proto_version(server_settings, TLS1_2_VERSION) != 1) 
		goto err;

	if (SSL_CTX_set_cipher_list(server_settings, cipher_list) != 1) 
		goto err;

	/* DEBUG: Temporary */
	if (SSL_CTX_load_verify_locations(server_settings, 
			"test_files/certs/rootCA.pem", NULL) != 1) {
		log_printf(LOG_DEBUG, "Failed to load verify location.\n");
		goto err;
	}


	if (SSL_CTX_use_certificate_chain_file(server_settings, 
			"test_files/certs/server_chain.pem") != 1) {
		log_printf(LOG_ERROR, "Failed to load cert chain\n");		
		goto err;
	}

	if (SSL_CTX_use_PrivateKey_file(server_settings, "test_files/certs/server_key.pem", 
			SSL_FILETYPE_PEM) != 1) {
		log_printf(LOG_ERROR, "Failed to load private key\n");
		goto err;
	}

	if (SSL_CTX_check_private_key(server_settings) != 1) {
		log_printf(LOG_ERROR, "Key and certificate don't match.\n");
		goto err;
	}

	if (SSL_CTX_build_cert_chain(server_settings, SSL_BUILD_CHAIN_FLAG_CHECK) != 1) {
		log_printf(LOG_ERROR, "Certificate chain failed to build.\n");
		goto err;
	}

	return server_settings;
 err:
	/* TODO: check and return OpenSSL error here? */
	ssl_err = ERR_get_error();
	char err_string[200] = {0};
	ERR_error_string_n(ssl_err, err_string, 200);
	log_printf(LOG_ERROR, "Server SSL_CTX failed with: %s\n", err_string);
	
	if (server_settings != NULL)
		SSL_CTX_free(server_settings);
    return NULL;
}

/**
 * Allocates a new SSL struct set with the daemon's set server settings.
 * On failure, the old SSL struct is preserved in the connection.
 */
int server_SSL_new(connection* conn, daemon_context* daemon) {
	
	SSL* temp = SSL_new(daemon->server_settings);
	if (temp == NULL) {
		/* TODO: determine if the error was actually an out-of-memory issue */
		return -ENOMEM;
	}
	
	if (conn->tls != NULL)
		SSL_free(conn->tls);

	conn->tls = temp;

	return 0;
}

int accept_SSL_new(connection* conn, connection* old) {
	if (conn->tls != NULL) 
		SSL_free(conn->tls);

	conn->tls = SSL_dup(old->tls);
	if (conn->tls == NULL) {
		/* TODO: get openssl error and return here */
		return -ENOMEM;
	} else {
		return 0;
	}
}

/**
 * Sets up and begins bufferevents for both the inner facing connection and
 * the secure external-facing TLS connection.
 * 
 * @returns 0 on success, or a negative errno error code otherwise. On error,
 * ifd and new_sock->fd will both be closed, and new_sock->fd will be set to
 * -1. ifd cannot be changed, as it is an argument to the function. As well,
 * the SSL object associated with new_sock will be freed.
 */
int accept_connection_setup(sock_context* new_sock, sock_context* old_sock, 
        evutil_socket_t ifd) {
    daemon_context* daemon = old_sock->daemon;
	connection* accept_conn = new_sock->conn;
	struct sockaddr* internal_addr = &old_sock->int_addr;
	int internal_addrlen = old_sock->int_addrlen;
	int ret = 0;

	accept_conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base, 
			new_sock->fd, new_sock->conn->tls, BUFFEREVENT_SSL_ACCEPTING, 0);

	if (accept_conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		/* free the SSL here (BEV_OPT_CLOSE_ON_FREE does everywhere else) */
		log_printf(LOG_ERROR, "Client bufferevent setup failed [listener]\n");
		goto err;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(accept_conn->secure.bev, 1);
	#endif
	
	accept_conn->plain.bev = bufferevent_socket_new(daemon->ev_base, 
			ifd, BEV_OPT_CLOSE_ON_FREE);

	if (accept_conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Server bev setup failed [listener]\n");
		goto err;
	}

	accept_conn->addr = internal_addr;
	accept_conn->addrlen = internal_addrlen;

	bufferevent_setcb(accept_conn->plain.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);
	bufferevent_setcb(accept_conn->secure.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);
	
	/* This will still result in a CONNECTED event--TLS also has to connect */
	ret = bufferevent_enable(accept_conn->secure.bev, EV_READ | EV_WRITE);
	if (ret != 0) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Secure bev enable failed [listener]\n");
		goto err;
	}

    return 0;
err:
	/* closing/freeing is left up to the calling function */
    return ret;
}



/*
 *******************************************************************************
 *                      SETSOCKOPT FUNCTIONS
 *******************************************************************************
 */
int set_remote_hostname(connection* conn_ctx, char* hostname) {
	if (conn_ctx == NULL) {
		/* We don't fail here because this will be set when the
		 * connection is actually created by tls_client_setup */
		return 1;
	}
	SSL_set_tlsext_host_name(conn_ctx->tls, hostname);
	return 1;
}
