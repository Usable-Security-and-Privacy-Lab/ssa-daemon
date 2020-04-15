#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>

#include "tls_server.h"
#include "tls_structs.h"
#include "log.h"

SSL_CTX* server_settings_init(char* path) {
	const char* cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
	SSL_CTX* server_settings = NULL;
	unsigned long ssl_err;

	server_settings = SSL_CTX_new(TLS_client_method());
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

int server_SSL_new(connection* conn, daemon_context* daemon) {
	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = SSL_new(daemon->server_settings);
	if (conn->tls == NULL) {
		/* TODO: determine if the error was actually an out-of-memory issue */
		return -ENOMEM;
	}
	return 0;
}

int accept_SSL_new(connection* conn, connection* old) {
	int ret = 0;

	/* if (conn->tls != NULL) 
		SSL_free(conn->tls); */
	conn->tls = SSL_dup(old->tls);
	if (conn->tls == NULL) {
		/* TODO: get openssl error and return here */
		ret = -ENOMEM;
	}
	return ret;
}

int accept_connection_setup(sock_context* new_sock, sock_context* old_sock, 
        evutil_socket_t ifd) {
    daemon_context* daemon = new_sock->daemon;
	connection* accept_conn = new_sock->conn;
	struct sockaddr* internal_addr = &old_sock->int_addr;
	int internal_addrlen = old_sock->int_addrlen;
	evutil_socket_t efd = new_sock->fd;
	int ret = 0;

	accept_conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base, 
			efd, accept_conn->tls, BUFFEREVENT_SSL_ACCEPTING, 
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (accept_conn->secure.bev == NULL) {
		ret = EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(efd);
		connection_free(accept_conn);
		goto err;
	}
	//accept_conn->secure.connected = 1;

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(accept_conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	accept_conn->plain.bev = bufferevent_socket_new(daemon->ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (accept_conn->plain.bev == NULL) {
		ret = EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(ifd);
		connection_free(accept_conn);
		goto err;
	}

	accept_conn->addr = internal_addr;
	accept_conn->addrlen = internal_addrlen;
	
	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(accept_conn->plain.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, accept_conn);
	//bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(accept_conn->secure.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, accept_conn);
	bufferevent_enable(accept_conn->secure.bev, EV_READ | EV_WRITE);

    return ret;
err:
    /* Do stuff here... */
    return ret;
}



/*
 **********************************
 * Function from setsockopt()
 **********************************
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