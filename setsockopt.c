#include <sys/stat.h>
#include <string.h>

#include <openssl/err.h>

#include "cipher_selection.h"
#include "error.h"
#include "log.h"
#include "sessions.h"
#include "setsockopt.h"
//#include "in_tls.h"



/* functions used for each option */
int set_CA_certificates(socket_ctx *sock_ctx, char* path, socklen_t len);
int set_certificate_chain(socket_ctx* sock_ctx, char* path, socklen_t len);
int set_private_key(socket_ctx* sock_ctx, char* path, socklen_t len);
int set_min_version(socket_ctx* sock_ctx, int* version, socklen_t len);
int set_max_version(socket_ctx* sock_ctx, int* version, socklen_t len);
int set_tls_context(socket_ctx* sock_ctx, unsigned long* data, socklen_t len);
int set_remote_hostname(socket_ctx* sock_ctx, char* hostname, socklen_t len);
int set_session_resumption(socket_ctx* sock_ctx, int* reuse, socklen_t len);

int set_revocation_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len);
int set_ocsp_stapled_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len);
int set_ocsp_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len);
int set_crl_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len);
int set_rev_cache_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len);

/* helper functions */
int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int check_key_cert_pair(socket_ctx* sock_ctx);


/**
 * Performs the socket operation specified by \p option on the given socket.
 * @param sock_ctx The context of the socket to perform the operation on.
 * @param option The operation to be performed.
 * @param value The value to be used in the operation (passed in by the 
 * calling program).
 * @param len The length of \p value.
 * @returns 0 on success, or a negative errno value on failure.
 */
int do_setsockopt_action(socket_ctx* sock_ctx, 
            int option, void* value, socklen_t len) {

    int response = 0;

    if (sock_ctx->has_shared_context && option != TLS_HOSTNAME)
        return -EOPNOTSUPP; /* TODO: determine appropriate errno */

    switch (option) {
    case TLS_HOSTNAME:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_remote_hostname(sock_ctx, (char*) value, len);
        break;

    case TLS_DISABLE_CIPHER:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = disable_ciphers(sock_ctx, (char*) value);
        break;

    case TLS_ENABLE_CIPHER:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = enable_cipher(sock_ctx, (char*) value);
        break;

    case TLS_TRUSTED_PEER_CERTIFICATES:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_CA_certificates(sock_ctx, (char*) value, len);
        break;

    case TLS_CERTIFICATE_CHAIN:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_certificate_chain(sock_ctx, (char*) value, len);
        break;

    case TLS_PRIVATE_KEY:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_private_key(sock_ctx, (char*) value, len);
        break;

    case TLS_VERSION_MIN:
	if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
//2, SOCKET_NEW, SOCKET_LISTENING) != 0) TODO: can listening sockets change version settings?
            break;
        response = set_min_version(sock_ctx, (int*) value, len);
        break;

    case TLS_VERSION_MAX:
	if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
//2, SOCKET_NEW, SOCKET_LISTENING) != 0) TODO: can listening sockets change version settings?
            break;
        response = set_max_version(sock_ctx, (int*) value, len);
        break;

    case TLS_REVOCATION_CHECKS:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_revocation_checks(sock_ctx, (int*) value, len);
        break;

    case TLS_OCSP_STAPLED_CHECKS:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_ocsp_stapled_checks(sock_ctx, (int*) value, len);
        break;

    case TLS_OCSP_CHECKS:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_ocsp_checks(sock_ctx, (int*) value, len);
        break;

    case TLS_CRL_CHECKS:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_crl_checks(sock_ctx, (int*) value, len);
        break;

    case TLS_CACHED_REV_CHECKS:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_rev_cache_checks(sock_ctx, (int*) value, len);
        break;

    case TLS_CONTEXT:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = set_tls_context(sock_ctx, (unsigned long*) value, len);
        break;

    case TLS_SESSION_REUSE:
        response = set_session_resumption(sock_ctx, (int*) value, len);
        break;

    default:
        response = -ENOPROTOOPT;
        break;
    }

    return response;
}


/**
 * Sets the certificate chain to be used for a given connection conn using 
 * the file/directory pointed to by path. 
 * @param conn The connection to load the certificate chain into.
 * @param path The path to the certificate chain directory/file.
 * @param len The length of \p path.
 * @returns 0 on success, or a negative errno if an error occurred.
 */
int set_certificate_chain(socket_ctx* sock_ctx, char* path, socklen_t len) {

    struct stat file_stats;
    int ret, response, ssl_err;

    if (strlen(path)+1 != len)
        return -EINVAL;

    ret = stat(path, &file_stats);
    if (ret != 0) {
        response = -EINVAL;
        goto err;
    }

    if (S_ISREG(file_stats.st_mode)) {
        /* is a file */
        ret = SSL_CTX_use_certificate_chain_file(sock_ctx->ssl_ctx, path);
        if (ret != 1) {
            response = -ECANCELED;
            goto err;
        }

    } else if (S_ISDIR(file_stats.st_mode)) {
        /* is a directory */
        /* TODO: add functionality for reading from folder.
         * See man fts for functions needed to do this */

        /* stub */
        response = -EINVAL;
        goto err;
    } else {
        /* could be a link, a socket, etc */
        response = -EINVAL;
        goto err;
    }

    return 0;
err:
    ssl_err = ERR_get_error();

    log_printf(LOG_ERROR, "Failed to load certificate chain: %s\n", 
            ssl_err ? ERR_error_string(ssl_err, NULL) : "not a file or folder");

    set_err_string(sock_ctx, "TLS error: couldn't set certificate chain - %s",
            ssl_err ? ERR_reason_error_string(ssl_err) : strerror(-ret));
    return response;
}



/**
 * Sets a private key for the given connection conn using the key located 
 * by path, and verifies that the given key matches the last loaded 
 * certificate chain. An SSL* can have multiple private key/cert chain pairs, 
 * so care should be taken to make sure they are loaded in the right sequence 
 * or else this function will fail.
 * @param conn The connection to add the given private key to.
 * @param path The location of the Private Key file.
 * @param len The length of \p path.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_private_key(socket_ctx* sock_ctx, char* path, socklen_t len) {

    struct stat file_stats;
    int ret;

    if (strlen(path)+1 != len)
        return -EINVAL;

    ret = stat(path, &file_stats);
    if (ret != 0) {
        ret = -errno;
        goto err;
    }
    if (!S_ISREG(file_stats.st_mode)) {
        ret = -EBADF;
        goto err;
    }

    ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, 
                path, SSL_FILETYPE_PEM);
    if (ret == 1) /* pem key loaded */
        return check_key_cert_pair(sock_ctx); 
    else
        clear_global_errors();

    ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, 
                path, SSL_FILETYPE_ASN1);
    if (ret == 1) /* ASN.1 key loaded */
        return check_key_cert_pair(sock_ctx);  
    else
        clear_global_errors();

    ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, 
                path, SSL_FILETYPE_PEM);
    if (ret == 1) /* pem RSA key loaded */
        return check_key_cert_pair(sock_ctx); 
    else
        clear_global_errors();

    ret = SSL_CTX_use_RSAPrivateKey_file(sock_ctx->ssl_ctx, 
                path, SSL_FILETYPE_ASN1);
    if (ret == 1) /* ASN.1 RSA key loaded */
        return check_key_cert_pair(sock_ctx);
    else
        goto err;

    return 0;
err:
    log_printf(LOG_ERROR, "Failed to set private key: %s\n", 
            ERR_reason_error_string(ERR_GET_REASON(ERR_peek_error())));
    set_err_string(sock_ctx, "TLS error: failed to set private key - %s",
            ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
    return -EBADF;
}

int set_min_version(socket_ctx *sock_ctx, int* version, socklen_t len) {

    int response = 0;
    if (*version != TLS_1_2 && *version != TLS_1_3) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN not TLS 1.2 or 1.3\n");
    }
    if (*version < get_tls_version(sock_ctx->daemon->settings->min_tls_version)) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN less than min in config file\n");
    }
    if (*version > SSL_CTX_get_max_proto_version(sock_ctx->ssl_ctx)) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MIN greater than current max\n");
    }
    if (!response)
        response = (SSL_CTX_set_min_proto_version(sock_ctx->ssl_ctx, *version) - 1);
        //we return 0 on success and -1 on failure
    return response;
}


int set_max_version(socket_ctx *sock_ctx, int* version, socklen_t len) {

    int response = 0;
    if (*version != TLS_1_2 && *version != TLS_1_3) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX not TLS 1.2 or 1.3\n");
    }
/*
    if (*version < get_tls_version(sock_ctx->daemon->settings->max_tls_version)) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX less than max in config file\n");
    }
*/ //TODO: what kind of settings should be discouraged for max version?
    if (*version < SSL_CTX_get_min_proto_version(sock_ctx->ssl_ctx)) {
        response = -EINVAL;
        log_printf(LOG_DEBUG, "Set TLS_VERSION_MAX less than current min\n");
    }
    if (!response)
        response = (SSL_CTX_set_max_proto_version(sock_ctx->ssl_ctx, *version) - 1);
        //we return 0 on success and -1 on failure
    return response;
}


/**
 * Sets the trusted Certificate Authority certificates for the given 
 * connection conn to those found in the file specified by path.
 * @param conn The connection to modify CA trusts on.
 * @param path The path to a file containing .pem encoded CA's.
 * @param len The length of \p path.
 * @returns 0 on success, or a negative errno if an error occurred.
 */
int set_CA_certificates(socket_ctx *sock_ctx, char* path, socklen_t len) {
    
    /* TODO: modify this to load client CAs from a folder as well */
    struct stat file_stats;
    int ret;

    if (strlen(path)+1 != len)
        return -EINVAL;

    if (stat(path, &file_stats) != 0) {
        set_err_string(sock_ctx, "Error: unable to open specified file");
        return -EINVAL;
    }
    
    if (S_ISREG(file_stats.st_mode)) { /* is a file */
        ret = SSL_CTX_load_verify_locations(sock_ctx->ssl_ctx, path, NULL);

    } else if (S_ISDIR(file_stats.st_mode)) { /* is a directory */
        ret = SSL_CTX_load_verify_locations(sock_ctx->ssl_ctx, NULL, path);
    
    } else {
        set_err_string(sock_ctx, "Error: path is not a file/directory");
        return -EINVAL;
    }

    if (ret != 1) {
        set_err_string(sock_ctx, "TLS error: unable to load CA certificates - %s",
                ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));

        return -ECANCELED;
    }

    return 0;
}

/**
 * Sets the hostname of the server that the calling program intends to connect 
 * to.
 * @param sock_ctx The context of the socket for the hostname to be set.
 * @param hostname The hostname that will be connected to.
 * @param len The length of \p hostname.
 */
int set_remote_hostname(socket_ctx* sock_ctx, char* hostname, socklen_t len) {

    if (len > MAX_HOSTNAME || len != strlen(hostname)+1)
        return -EINVAL;

    memcpy(sock_ctx->rem_hostname, hostname, len);

    log_printf(LOG_INFO, "Hostname set to %s\n", sock_ctx->rem_hostname);

    return 0;
}


/**
 * Sets the SSL context of the given socket to be identical to another 
 * socket. The other socket is retrieved via its ID, which is passed in 
 * through \p data.
 * @param sock_ctx The context of the socket to set the SSL context for.
 * @param data A byte stream of data representing the ID of the socket 
 * to clone the SSL context of.
 * @param len The size of \p data.
 * @returns 0 on success, or a negative errno value on failure.
 */
int set_tls_context(socket_ctx* sock_ctx, unsigned long* data, socklen_t len) {

    unsigned long id = *data;
    socket_ctx* old_sock_ctx;

    if (len != sizeof(unsigned long))
        return -EINVAL;

    old_sock_ctx = hashmap_get(sock_ctx->daemon->sock_map, id);
    if (old_sock_ctx == NULL)
        return -EINVAL;

    if (has_session_cache(old_sock_ctx->ssl_ctx)) {
        int response = session_cache_up_ref(old_sock_ctx->ssl_ctx);
        if (response != 0)
            return response;
    }

    SSL_CTX_free(sock_ctx->ssl_ctx);
    sock_ctx->ssl_ctx = old_sock_ctx->ssl_ctx;
    SSL_CTX_up_ref(sock_ctx->ssl_ctx);

    /* copy in the hostname */
    strcpy(sock_ctx->rem_hostname, old_sock_ctx->rem_hostname);

    return 0;
}


/**
 * Sets the given socket to attempt session resumption and cache sessions 
 * (or to never attempt resumptions and never cache sessions). 
 * This function applies these features to both client and server sockets.
 * @param sock_ctx The context of the socket to turn session resumption on/off 
 * for.
 * @param reuse Pointer to whether the socket should use sessions (1) or 
 * not (0).
 * @param len the size of \p reuse.
 * @returns 0 on success, or a negative errno value on failure.
 */
int set_session_resumption(socket_ctx* sock_ctx, int* reuse, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;

    if (*reuse == 1 && settings->session_resumption == 0)
        return -EPROTO;

    if (*reuse == 1)
        SSL_CTX_set_session_cache_mode(sock_ctx->ssl_ctx, SSL_SESS_CACHE_BOTH);
    else if (*reuse == 0)
        SSL_CTX_set_session_cache_mode(sock_ctx->ssl_ctx, SSL_SESS_CACHE_OFF);
    else
        return -EINVAL;

    /* BUG: Servers with these settings may still *send* tickets; they just 
     * won't accept them as valid once presented. See `SSL_CTX_set_num_tickets`
     */
    return 0;
}

int set_revocation_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;

    if (*enabled == 0 && has_revocation_checks(settings->revocation_checks))
        return -EPROTO; /* fail if disabling when config has checks enforced */
    
    if (*enabled == 1)
        turn_on_revocation_checks(sock_ctx->rev_ctx->checks);
    else if (*enabled == 0)
        turn_off_revocation_checks(sock_ctx->rev_ctx->checks);
    else
        return -EINVAL;

    return 0;
}

int set_ocsp_stapled_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;

    if (*enabled == 1 && !has_stapled_checks(settings->revocation_checks))
        return -EPROTO; /* fail if enabling when config disables it */
    
    if (*enabled == 1)
        turn_on_stapled_checks(sock_ctx->rev_ctx->checks);
    else if (*enabled == 0)
        turn_off_stapled_checks(sock_ctx->rev_ctx->checks);
    else
        return -EINVAL;

    return 0;
}

int set_ocsp_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;

    if (*enabled == 1 && !has_ocsp_checks(settings->revocation_checks))
        return -EPROTO; /* fail if enabling when config disables it */
    
    if (*enabled == 1)
        turn_on_ocsp_checks(sock_ctx->rev_ctx->checks);
    else if (*enabled == 0)
        turn_off_ocsp_checks(sock_ctx->rev_ctx->checks);
    else
        return -EINVAL;

    return 0;
}

int set_crl_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;

    if (*enabled == 1 && !has_crl_checks(settings->revocation_checks))
        return -EPROTO; /* fail if enabling when config disables it */
    
    if (*enabled == 1)
        turn_on_crl_checks(sock_ctx->rev_ctx->checks);
    else if (*enabled == 0)
        turn_off_crl_checks(sock_ctx->rev_ctx->checks);
    else
        return -EINVAL;

    return 0;
}

int set_rev_cache_checks(socket_ctx* sock_ctx, int* enabled, socklen_t len) {

    global_config* settings = sock_ctx->daemon->settings;

    if (len != sizeof(int))
        return -EINVAL;
    
    if (*enabled == 1 && !has_cached_checks(settings->revocation_checks))
        return -EPROTO; /* fail if enabling when config disables it */
    
    if (*enabled == 1)
        turn_on_cached_checks(sock_ctx->rev_ctx->checks);
    else if (*enabled == 0)
        turn_off_cached_checks(sock_ctx->rev_ctx->checks);
    else
        return -EINVAL;

    return 0;
}



/*******************************************************************************
 *                             HELPER FUNCTIONS
 ******************************************************************************/



/**
 * Iterates through the stack of ciphers and clears out ones matching
 * the given cipher name. Returns the updated cumulative length of the ciphers.
 * @param cipher The string name of the cipher to be cleared from the list.
 * @param cipherlist The stack of ciphers to be modified.
 * @returns 0 on success, or -1 if the cipher was not found.
 */
int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist) {
    int i = 0, has_cipher = 0;

    while (i < sk_SSL_CIPHER_num(cipherlist)) {
        const SSL_CIPHER* curr_cipher = sk_SSL_CIPHER_value(cipherlist, i);
        const char* name = SSL_CIPHER_get_name(curr_cipher);
        if (strcmp(name, cipher) == 0) {
            has_cipher = 1;
            sk_SSL_CIPHER_delete(cipherlist, i);
            /* SSL_CIPHER_free(curr_cipher) */;
        } else {
            i++;
        }
    }
    /* assert: all ciphers to remove now removed */

    if (has_cipher)
        return 0;
    else
        return -1;
}

/** 
 * Verifies that the loaded private key and certificate match each other.
 * @pre The Private Key and Certificate chain have already been loaded into
 * tls.
 * @param tls The SSL object containing the certificate chain and private key
 * for which to check.
 * @returns 0 if the checks succeeded; -EPROTO otherwise. 
 */
int check_key_cert_pair(socket_ctx* sock_ctx) {
    if (SSL_CTX_check_private_key(sock_ctx->ssl_ctx) != 1) {
        log_printf(LOG_ERROR, "Key and certificate don't match.\n");
        set_err_string(sock_ctx, "TLS error: certificate/privateKey mismatch - %s",
                ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
        goto err;
    }

    if (SSL_CTX_build_cert_chain(sock_ctx->ssl_ctx, SSL_BUILD_CHAIN_FLAG_CHECK) != 1) {
        log_printf(LOG_ERROR, "Certificate chain failed to build.\n");
        set_err_string(sock_ctx, "TLS error: privateKey/cert chain incomplete - %s",
                ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
        goto err;
    }

    return 0;
err:
    return -EPROTO; /* Protocol err--key didn't match or chain didn't build */
}
