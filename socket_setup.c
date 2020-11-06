#include <fcntl.h> /* for S_IFDIR/S_IFREG constants */
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>

#include "certificate.h"
#include "config.h"
#include "connection_callbacks.h"
#include "error.h"
#include "in_tls.h"
#include "log.h"
#include "sessions.h"
#include "socket_setup.h"

#define UBUNTU_DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define FEDORA_DEFAULT_CA "/etc/pki/tls/certs/ca-bundle.crt"

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

#define DEBUG_TEST_CA "test_files/certs/rootCA.pem"
#define DEBUG_CERT_CHAIN "test_files/certs/server_chain.pem"
#define DEBUG_PRIVATE_KEY "test_files/certs/server_key.pem"

#define EXT_CONN_TIMEOUT 15 /* seconds */



/* SSL_CTX loading */

int load_certificate_authority(SSL_CTX* ctx, char* CA_path);
int load_cipher_list(SSL_CTX* ctx, char** list, int num);
int load_ciphersuites(SSL_CTX* ctx, char** list, int num);

int concat_ciphers(char** list, int num, char** out);

int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int check_key_cert_pair(socket_ctx* sock_ctx);

/**
 * Allocates an SSL_CTX struct and populates it with the settings found in 
 * \p settings. 
 * @param settings a struct filled with the settings that should be applied
 * to the SSL_CTX.
 * @returns A pointer to an allocated SSL_CTX struct, or NULL on error.
 */
SSL_CTX* SSL_CTX_create(global_config* settings) {

    SSL_CTX* ctx = NULL;
    long tls_version;
    int ret;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto err;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (settings->session_resumption) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(ctx, 0);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    }


    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if (!settings->session_tickets)
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    else
        SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
    

    tls_version = tls_version_to_openssl(settings->min_tls_version);
	if (SSL_CTX_set_min_proto_version(ctx, tls_version) != 1) 
		goto err;

	tls_version = tls_version_to_openssl(settings->max_tls_version);
	if (SSL_CTX_set_max_proto_version(ctx, tls_version) != 1)
		goto err;


	if (settings->cipher_list_cnt > 0) {
		ret = load_cipher_list(ctx, 
				settings->cipher_list, settings->cipher_list_cnt);
	} else {
		ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	}
	if (ret != 1)
		goto err;
	

	if (settings->ciphersuite_cnt > 0) {
		ret = load_ciphersuites(ctx, 
				settings->ciphersuites, settings->ciphersuite_cnt);
	} else {
		ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	}
	if (ret != 1)
		goto err;

	ret = load_certificate_authority(ctx, settings->ca_path);
	if (ret != 1)
		goto err;

	SSL_CTX_set_timeout(ctx, settings->session_timeout);
	SSL_CTX_set_verify_depth(ctx, settings->max_chain_depth);

	if(settings->ct_checks) {
		ret = SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_STRICT);
		if (ret != 1)
			goto err;

		ret = SSL_CTX_set_ctlog_list_file(ctx, "ct_log_list.cnf");
		if(ret != 1)
			goto err;
	}

	for(int i = 0; i < settings->cert_cnt; ++i) {
		ret = load_certificates(ctx, settings->certificates[i]); // eventually delete this
		if (ret != 1) 
			goto err;

		ret = load_private_key(ctx, settings->private_keys[i]); 
		if(ret != 1) 
			goto err;
		
	}

	return ctx;
err:
    if (ERR_peek_error())
        LOG_E("OpenSSL error initializing client SSL_CTX: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
    
    if (ctx != NULL)
        SSL_CTX_free(ctx);

    return NULL;
}


/**
 * Allocates and sets the correct settings for the bufferevents of a given 
 * socket. The socket may be either a connecting client socket (in which case 
 * the plain_fd must be set to -1) or an `accept()`ed server socket (in which
 * case the plain_fd must be set to the fd of the socket).
 * @param sock_ctx The context of the socket to prepare bufferevents for.
 * @param plain_fd The file descriptor that will be connected internally to
 * our program.
 * @returns 0 on success, or a negative errno code on failure. The bufferevents 
 * and the plain_fd are cleaned up on failure.
 */
int prepare_bufferevents(socket_ctx* sock_ctx, int plain_fd) {

    daemon_ctx* daemon = sock_ctx->daemon;
    enum bufferevent_ssl_state state;
    bufferevent_event_cb event_cb;
    int ret;

    if (plain_fd == NO_FD) {
        state = BUFFEREVENT_SSL_CONNECTING;
        event_cb = client_bev_event_cb;
    
    } else {
        state = BUFFEREVENT_SSL_ACCEPTING;
        event_cb = server_bev_event_cb;
    }

    clear_global_and_socket_errors(sock_ctx);

    sock_ctx->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base,
                sock_ctx->sockfd, sock_ctx->ssl, state, BEV_OPT_CLOSE_ON_FREE);
    if (sock_ctx->secure.bev == NULL)
        goto err;

    bufferevent_openssl_set_allow_dirty_shutdown(sock_ctx->secure.bev, 1);

    ret = bufferevent_enable(sock_ctx->secure.bev, EV_READ | EV_WRITE);
    if (ret < 0)
        goto err;

    sock_ctx->plain.bev = bufferevent_socket_new(daemon->ev_base,
                plain_fd, BEV_OPT_CLOSE_ON_FREE);
    if (sock_ctx->plain.bev == NULL)
        goto err;

    bufferevent_setcb(sock_ctx->secure.bev, common_bev_read_cb,
            common_bev_write_cb, event_cb, sock_ctx);
    bufferevent_setcb(sock_ctx->plain.bev, common_bev_read_cb,
            common_bev_write_cb, event_cb, sock_ctx);

     return 0;
err:
    log_global_error(LOG_ERR, "Failed to set up bufferevents for connection");

    if (sock_ctx->plain.bev != NULL) {
        bufferevent_free(sock_ctx->plain.bev);
        sock_ctx->plain.bev = NULL;

    } else if (plain_fd != NO_FD) {
        close(plain_fd);
    }

    if (sock_ctx->secure.bev != NULL) {
        bufferevent_free(sock_ctx->secure.bev);

        sock_ctx->secure.bev = NULL;
        sock_ctx->ssl = NULL;
        sock_ctx->sockfd = NO_FD;
    }
    
    sock_ctx->state = SOCKET_ERROR;

    return -ECANCELED;
}


/**
 * Prepares the given socket context for a TLS connection with an endpoint. 
 * This function mostly has to do with setting up the `SSL` object used by 
 * the socket--allocation, setting it to perform certificate verification, 
 * giving it a session to resume (if one exists), and assigning it the hostname 
 * in \p sock_ctx.
 * @param sock_ctx The context of the socket to prepare an SSL object for. 
 * @returns 0 on success, or a negative errno value if an error occurred.
 */
int prepare_SSL_client(socket_ctx* sock_ctx) {

    int ret;

    if (has_revocation_checks(sock_ctx->flags))

        ret = SSL_CTX_set_tlsext_status_type(sock_ctx->ssl_ctx, 
                    TLSEXT_STATUSTYPE_ocsp);
    else
        ret = SSL_CTX_set_tlsext_status_type(sock_ctx->ssl_ctx, 0);

    if (ret != 1)
        goto err;

    sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        goto err;

    SSL_set_verify(sock_ctx->ssl, SSL_VERIFY_PEER, NULL);

    if (strlen(sock_ctx->rem_hostname) <= 0) {
        set_err_string(sock_ctx, "TLS error: "
                    "hostname required for verification (via setsockopt())");
        goto err;
    }

    ret = SSL_set_tlsext_host_name(sock_ctx->ssl, sock_ctx->rem_hostname);
    if (ret != 1) {
        LOG_E("Connection setup error: "
                "couldn't assign the socket's hostname for SNI\n");
        goto err;
    }

    ret = SSL_set1_host(sock_ctx->ssl, sock_ctx->rem_hostname);
    if (ret != 1) {
        LOG_E("Connection setup error: "
                "couldn't assign the socket's hostname for validation\n");
        goto err;
    }
    if (session_resumption_enabled(sock_ctx->ssl_ctx)) {
        char* host_port = get_hostname_port_str(sock_ctx);
        if (host_port == NULL)
            goto err;

        ret = session_resumption_setup(sock_ctx->ssl, host_port);
        if (ret != 0) {
            free(host_port);
            goto err;
        }
    }

    return 0;
err:

    if (sock_ctx->ssl != NULL)
        SSL_free(sock_ctx->ssl);
    sock_ctx->ssl = NULL;

    if (has_error_string(sock_ctx))
        return -EPROTO;

    return -ECANCELED;
}


/**
 * Allocates an SSL object for a connection accepted by a server.
 * @param sock_ctx The context of the socket to prepare the SSL object for.
 * @returns 0 on success, or a negative errno on failure.
 */
int prepare_SSL_server(socket_ctx* sock_ctx) {

    sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        return -ECANCELED;

    return 0;
}



/**
 *******************************************************************************
 *               HELPER FUNCTIONS FOR CONFIG LOADING/SOCKOPTS
 *******************************************************************************
 */

/**
 * Converts the given tls_version into the OpenSSL-specific version.
 * @param version The version given to us (by config file or setsockopt call).
 * @returns The OpenSSL representation of the TLS Version, or TLS1_MAX_VERSION
 * if no version was set (a safe default).
 */
int tls_version_to_openssl(short version) {

    switch (version) {
        case TLS_1_0:
            return TLS1_VERSION;
        case TLS_1_1:
            return TLS1_1_VERSION;
        case TLS_1_2:
            return TLS1_2_VERSION;
        case TLS_1_3:
            return TLS1_3_VERSION;
        default:
            return TLS_MAX_VERSION;
    }
}

short tls_version_from_openssl(int version) {

    switch (version) {
        case TLS1_VERSION:
            return TLS_1_0;
        case TLS1_1_VERSION:
            return TLS_1_1;
        case TLS1_2_VERSION:
            return TLS_1_2;
        case TLS1_3_VERSION:
            return TLS_1_3;
        default:
            return -1;
    }
}

/**
 * Erases all previously-set ciphers in ciphers and sets them to the list of
 * ciphers in list.
 * @param ctx The context to load the given ciphers into.
 * @param list The list of names of ciphers to load.
 * @param num The size of list.
 * @returns 1 on success, or 0 if some of the ciphers could not be added.
 */
int load_cipher_list(SSL_CTX* ctx, char** list, int num) {

    char* ciphers;
    int ret;

    ret = concat_ciphers(list, num, &ciphers);
    if (ret != 1)
        return 0;

    ret = SSL_CTX_set_cipher_list(ctx, ciphers);
    if (ret != 1)
        goto end;
    
    /* returns some false negatives... but it's the best we've got */
    if (sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx)) < num) {
        /* Fewer ciphers were added than were specified */
        LOG_E("Some cipher names were not recognized\n");
        ret = 0;
        goto end;
    }

end:
    free(ciphers);
    return ret;
}

/**
 * Erases all previously-set TLS 1.3 ciphers in ciphers and sets them to the
 * list of ciphers in list.
 * @param ctx The context to load the given ciphers into.
 * @param list The list of names of ciphers to load.
 * @param num The size of list.
 * @returns 1 on success, or 0 if some of the ciphers could not be added.
 */
int load_ciphersuites(SSL_CTX* ctx, char** list, int num) {

    char* ciphers;
    int ret;

    ret = concat_ciphers(list, num, &ciphers);
    if (ret != 1)
        return 0;

    ret = SSL_CTX_set_ciphersuites(ctx, ciphers);
    if (ret != 1)
        goto end;

    if (sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx)) < num) {
        LOG_E("Some cipher names were not recognized\n");
        ret = 0;
        goto end;
    }

end:
    free(ciphers);
    return ret;
}

/**
 * Helper function for load_cipher_list and load_ciphersuites; takes a given
 * list of ciphers and converts them into the OpenSSL-defined format required
 * to set the cipher list or ciphersuites.
 * @param list The list of ciphers to be converted into OpenSSL cipherlist 
 * format.
 * @param num The number of ciphers in list.
 * @param out The converted cipherlist string (NULL-terminated).
 * @returns 1 on success, or 0 on error.
 */
int concat_ciphers(char** list, int num, char** out) {

    char* ciphers;
    int offset = 0;
    int len = 0;

    for (int i = 0; i < num; i++)
        len += strlen(list[i]) + 1; /* +1 for colon (or '\0' at end) */

    ciphers = malloc(len);
    if (ciphers == NULL) {
        LOG_E("Malloc failed while loading cipher list: %s\n",
                strerror(errno));
        return 0;
    }

    for (int i = 0; i < num; i++) {
        int cipher_len = strlen(list[i]);

        memcpy(&ciphers[offset], list[i], cipher_len);
        ciphers[offset + cipher_len] = ':';

        offset += cipher_len + 1;
    }

    ciphers[len - 1] = '\0';

    if (len != offset) {
        log_printf(LOG_WARNING, "load_cipher_list had unexpected results\n");
        free(ciphers);
        return 0;
    }

    *out = ciphers;
    return 1;
}


/**
 * Verifies that a given path is a file that contains valid certificate 
 * authority X509 certificates.
 * @param CA_path A path that should contain certificate authorities.
 * @returns 0 on success, or -1 if the path failed verification.
 */
int test_certificate_authority(char *CA_path) {

    SSL_CTX *ctx;
    int ret;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        LOG_E("Certificate authority could not be verified: out of memory\n");

        errno = 0;
        return -1;
    }

    ret = load_certificate_authority(ctx, CA_path);
    if (ret != 1) {
        unsigned long ssl_err = ERR_get_error();
        if (ssl_err != 0)
            LOG_E("Certificate authority could not be parsed: %s\n",
                  ERR_reason_error_string(ssl_err));

        errno = 0;
        return -1;
    }

    return 0;
}

/**
 * Loads the given certificate authority .pem or .der-encoded certificates into
 * ctx from the file or directory specified by path. This function will load in
 * all certificates found in a directory, or all certificates found in an 
 * individual file (if the file is capable of containing more than one 
 * certificate). If CA_path is null, this function will attempt to find the 
 * default location of CA certificates on your machine.
 * @param ctx The SSL_CTX to load certificate authorities in to.
 * @param CA_path A NULL-terminated string representing the path to the 
 * directory/file; or NULL if the default locations are desired.
 * @returns 1 on success, or 0 if an error occurred.
 */
int load_certificate_authority(SSL_CTX* ctx, char* CA_path) {

    struct stat file_stats;

    /* TODO: Add all potential OS paths here */
    if (CA_path == NULL) { /* No CA file given--search for one based on system */
        if (access(UBUNTU_DEFAULT_CA, F_OK) != -1) {
            CA_path = UBUNTU_DEFAULT_CA;
            /* log_printf(LOG_INFO, "Found the Ubuntu CA file.\n"); */
        
        } else if(access(FEDORA_DEFAULT_CA, F_OK) != -1) {
            CA_path = FEDORA_DEFAULT_CA;
            /* log_printf(LOG_INFO, "Found the Fedora CA file.\n"); */
        
        } else { /* UNSUPPORTED OS */
            /* LOG_E("Unable to find valid CA location.\n"); */
            return 0;
        }
    }

    
    if (stat(CA_path, &file_stats) != 0) {
        LOG_E("Failed to access CA file %s: %s\n", 
                CA_path, strerror(errno));
        return 0;
    }

    if (S_ISREG(file_stats.st_mode)) {
        /* is a file */
        return SSL_CTX_load_verify_locations(ctx, CA_path, NULL);

    } else if (S_ISDIR(file_stats.st_mode)) {
        /* is a directory */
        return SSL_CTX_load_verify_locations(ctx, NULL, CA_path);

    } else {
        LOG_E("Loading CA certs--path not file or directory\n");
        return 0;
    }
}


/**
 * Associates the given file descriptor with the given connection and 
 * enables its bufferevent to read and write freely.
 * @param sock_ctx The connection to have the file descriptor associated with.
 * @param ifd The file descriptor of an internal program that will
 * communicate to the daemon through plaintext.
 * @returns 0 on success, or -ECONNABORTED on failure.
 */
int associate_fd(socket_ctx* sock_ctx, evutil_socket_t ifd) {

    /* Possibility of failure is acutally none in current libevent code */
    if (bufferevent_setfd(sock_ctx->plain.bev, ifd) != 0)
        goto err;

    /* This function *unlikely* to fail, but if we want to be really robust...*/
    if (bufferevent_enable(sock_ctx->plain.bev, EV_READ | EV_WRITE) != 0)
        goto err;

    return 0;
err:
    LOG_E("associate_fd failed.\n");
    return -ECONNABORTED; /* Only happens while client is connecting */
}
