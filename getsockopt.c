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

#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socket_setup.h"
#include "cipher_selection.h"
#include "error.h"
#include "getsockopt.h"
#include "in_tls.h"
#include "log.h"
#include "sessions.h"


int get_peer_certificate(socket_ctx* sock_ctx, char** data, unsigned int* len);
int get_peer_identity(socket_ctx* sock_ctx, char** data, unsigned int* len);
int get_hostname(socket_ctx* sock_ctx, char** data, unsigned int* len);
int get_chosen_cipher(socket_ctx* sock_ctx, char** data, unsigned int* len);
int get_version_min(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_version_max(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_version_conn(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_session_resumed(socket_ctx* sock_ctx, int** data, unsigned int *len);
int get_session_reuse(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_server_stapling(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_tls_context(socket_ctx* sock_ctx, 
            unsigned long** data, unsigned int* len);

/* revocation settings/methods */
int get_revocation_checks(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_stapled_checks(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_ocsp_checks(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_crl_checks(socket_ctx* sock_ctx, int** data, unsigned int* len);
int get_cached_checks(socket_ctx* sock_ctx, int** data, unsigned int* len);


/**
 * Performs the operations necessary to retrieve the specified information 
 * desired for the given socket.
 * @param sock_ctx The context of the socket to retrieve information from.
 * @param option The socket option to retrieve information associated with.
 * @param need_free Whether \p data will need to be freed after use.
 * @param data A pointer to data to be sent back to the calling program.
 * @param len The size of \p data.
 * @returns 0 on success, or a negative errno value on failure.
 */
int do_getsockopt_action(socket_ctx* sock_ctx, 
            int option, void** data, unsigned int* len) {

    int response = 0;

    switch (option) {
    case TLS_ERROR:
        if (!has_error_string(sock_ctx)) {
            response = -EINVAL;
            break;
        }

        *len = strlen(sock_ctx->err_string) + 1;
        *data = strdup(sock_ctx->err_string);
        if (*data == NULL)
            response = -ECANCELED;
        break;

    case TLS_HOSTNAME:
        if ((response = check_socket_state(sock_ctx, SOCKET_NEW)) != 0)
            break;
        response = get_hostname(sock_ctx, (char**) data, len);
        break;

    case TLS_PEER_IDENTITY:
        if ((response = check_socket_state(sock_ctx, SOCKET_CONNECTED)) != 0)
            break;

        response = get_peer_identity(sock_ctx, (char**) data, len);
        break;

    case TLS_PEER_CERTIFICATE_CHAIN:
        if ((response = check_socket_state(sock_ctx, SOCKET_CONNECTED)) != 0)
            break;
        response = get_peer_certificate(sock_ctx, (char**) data, len);
        break;

    case TLS_TRUSTED_CIPHERS:
        response = get_enabled_ciphers(sock_ctx, (char**) data, len);
        break;

    case TLS_CHOSEN_CIPHER:
        if ((response = check_socket_state(sock_ctx, SOCKET_CONNECTED)) != 0)
            break;
        get_chosen_cipher(sock_ctx, (char**) data, len);
        break;

    case TLS_VERSION_MIN:
        get_version_min(sock_ctx, (int**) data, len);
        break;

    case TLS_VERSION_MAX:
        get_version_max(sock_ctx, (int**) data, len);
        break;

    case TLS_VERSION_CONN:
        if ((response = check_socket_state(sock_ctx, SOCKET_CONNECTED)) != 0)
            break;
        get_version_conn(sock_ctx, (int**) data, len);
        break;

    case TLS_REVOCATION_CHECKS:
        response = get_revocation_checks(sock_ctx, (int**) data, len);
        break;

    case TLS_OCSP_STAPLED_CHECKS:
        response = get_stapled_checks(sock_ctx, (int**) data, len);
        break;

    case TLS_OCSP_CHECKS:
        response = get_ocsp_checks(sock_ctx, (int**) data, len);
        break;

    case TLS_CRL_CHECKS:
        response = get_crl_checks(sock_ctx, (int**) data, len);
        break;

    case TLS_CACHED_REV_CHECKS:
        response = get_cached_checks(sock_ctx, (int**) data, len);
        break;

    case TLS_CONTEXT:
        if ((response = check_socket_state(sock_ctx, SOCKET_NEW)) != 0)
            break;
        response = get_tls_context(sock_ctx, (unsigned long**) data, len);
        break;

    case TLS_RESUMED_SESSION:
        if ((response = check_socket_state(sock_ctx, SOCKET_CONNECTED)) != 0)
            break;
        response = get_session_resumed(sock_ctx, (int**) data, len);
        break;
    
    case TLS_SESSION_REUSE:
        response = get_session_reuse(sock_ctx, (int**) data, len);
        break;

    case TLS_SERVER_OCSP_STAPLING:
        response = get_server_stapling(sock_ctx, (int**) data, len);
        break;

    case TLS_TRUSTED_PEER_CERTIFICATES:
    case TLS_PRIVATE_KEY:
    case TLS_DISABLE_CIPHER:
    case TLS_REQUEST_PEER_AUTH:
        response = -ENOPROTOOPT; /* all set only */
        break;

    case TLS_ID:
        /* This case is handled directly by the kernel.
         * If we want to change that, uncomment the lines below */
        /* data = &id;
        len = sizeof(id);
        break; */
    default:
        log_printf(LOG_ERR,
                "Default case for getsockopt hit: should never happen\n");
        response = -EBADF;
        break;
    }

    return response;
}


int get_server_stapling(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    if (len == NULL || data == NULL || *len < sizeof(int))
        return -EINVAL;

    int* is_stapling = malloc(sizeof(int));
    if (is_stapling == NULL)
        return -ECANCELED;

    *is_stapling = server_stapling_enabled(sock_ctx->flags) ? 1 : 0;
    *data = is_stapling;
    *len = sizeof(int);
    
    return 0;
}


/**
 * Retrieves the peer's certificate (if such exists) and allocates data to a
 * PEM-formatted string representing that certificate.
 * @param conn The connection context to retrieve a peer certificate from.
 * @param data A memory address for the certificate string to be allocated to.
 * @param len The string length of the certificate.
 * @returns 0 on success; -errno otherwise.
 */
int get_peer_certificate(socket_ctx* sock_ctx, 
            char** data, unsigned int* len) {
    X509* cert = NULL;
    BIO* bio = NULL;
    char* bio_data = NULL;
    char* pem_data = NULL;
    unsigned int cert_len;
    int ret;

    cert = SSL_get_peer_certificate(sock_ctx->ssl);
    if (cert == NULL) {
        set_err_string(sock_ctx, "TLS error: peer certificate not found");
        ret = -ENOTCONN;
        goto end;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ret = determine_and_set_error(sock_ctx);
        goto end;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        ret = determine_and_set_error(sock_ctx);
        goto end;
    }

    cert_len = BIO_get_mem_data(bio, &bio_data);
    pem_data = malloc(cert_len + 1); /* +1 for null terminator */
    if (pem_data == NULL) {
        ret = -errno;
        set_err_string(sock_ctx, "Daemon error: failed to allocate buffers");
        goto end;
    }

    memcpy(pem_data, bio_data, cert_len);
    pem_data[cert_len] = '\0';

    ret = 0;
    *data = pem_data;
    *len = cert_len + 1;
end:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

/**
 * Retrieves the identity of the peer currently connected to in conn. The 
 * identity is stored in the X509 certificate that the peer had sent to use 
 * in the TLS handshake.
 * @param conn The connection to retrieve peer identity information for.
 * @param identity An area to allocate the ASCII representation of the peer's 
 * identity to.
 * @param len The length of identity.
 * @returns 0 on success; or -errno if an error occurred.
 */
int get_peer_identity(socket_ctx* sock_ctx, 
            char** identity, unsigned int* len) {
    
    X509_NAME* subject_name;
    X509* cert;

    cert = SSL_get_peer_certificate(sock_ctx->ssl);
    if (cert == NULL) {
        set_err_string(sock_ctx, "TLS error: couldn't get peer certificate - %s",
                ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
        return -ENOTCONN;
    }

    subject_name = X509_get_subject_name(cert);
    if (subject_name == NULL) {
        set_err_string(sock_ctx, "TLS error: peer's certificate has no identity");
        return -EINVAL;
    }

    *identity = X509_NAME_oneline(subject_name, NULL, 0);
    if (*identity == NULL) {
        X509_free(cert);
        return determine_and_set_error(sock_ctx);
    }
    *len = strlen(*identity) + 1; /* '\0' character */

    X509_free(cert);
    return 0;
}


/**
 * Retrieves the given connection's assigned hostname (as used in SNI
 * indication). Note that this does not retrieve the hostname of a server a 
 * client has connected to; rather, this retrieves the hostname that has
 * been assigned to the given connection, assuming that the given connection
 * is a server.
 * @param conn The connection to retrieve a hostname from.
 * @param data The string that hostname will be assigned to.
 * @param len The length of hostname (including the null-terminating character).
 * @returns 0 on success, or -errno if an error has occurred.
 */
int get_hostname(socket_ctx* sock_ctx, char** data, unsigned int* len) {

    /*
    hostname = SSL_get_servername(sock_ctx->ssl, TLSEXT_NAMETYPE_host_name);
    if (hostname == NULL) {
        set_err_string(sock_ctx, "TLS error: couldn't get the server hostname - %s",
                ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
        return -EINVAL;
    }
    */

    if (strlen(sock_ctx->rem_hostname) == 0) {
        set_err_string(sock_ctx, "No hostname was set for the given socket");
        return -EINVAL;
    }

    *len = strlen(sock_ctx->rem_hostname)+1;
    *data = strdup(sock_ctx->rem_hostname);
    if (*data == NULL)
        return -ECANCELED;

    return 0;
}




/**
 * Returns the cipher currently in use for the connection.
 * @param sock_ctx The context of the currently connected socket to retrieve
 * cipher information from.
 * @param len The ouptut length of the cipher.
 * @returns A null-terminated string representing the cipher in current use.
 */
int get_chosen_cipher(socket_ctx* sock_ctx, char** data, unsigned int* len) {
    
    const char* cipher = SSL_get_cipher(sock_ctx->ssl);
    if (cipher == NULL)
        return -EINVAL;

    *len = strlen(*data) + 1;
    *data = strdup(cipher);
    if (*data == NULL)
        return -ECANCELED;

    return 0;
}


/**
 * Returns the minimum TLS version accepted by the socket.
 * @param sock_ctx The context of the socket to retrieve TLS version constrints 
 * for.
 * @param data [out] A newly-allocated pointer to a version number.
 * @param len [out] The length of \p data.
 * @returns 0 on success, or a negative errno on failure.
 */
int get_version_min(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* version = malloc(sizeof(int));
    if (version == NULL)
        return -ENOMEM;

    int openssl_version = SSL_CTX_get_min_proto_version(sock_ctx->ssl_ctx);
    *version = tls_version_from_openssl(openssl_version);

    *data = version;
    *len = sizeof(int);

    return 0;
}

/**
 * Returns the maximum TLS version accepted by the socket.
 * @param sock_ctx The context of the socket to retrieve TLS version constrints 
 * for.
 * @param data [out] A newly-allocated pointer to a version number.
 * @param len [out] The length of \p data.
 * @returns 0 on success, or a negative errno on failure.
 */
int get_version_max(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* version = malloc(sizeof(int));
    if (version == NULL)
        return -ENOMEM;

    int openssl_version = SSL_CTX_get_max_proto_version(sock_ctx->ssl_ctx);
    *version = tls_version_from_openssl(openssl_version);

    *data = version;
    *len = sizeof(int);

    return 0;
}

/**
 * Returns the TLS version being used in the socket's connection.
 * @param sock_ctx The context of the socket to retrieve TLS version constrints 
 * for.
 * @param data [out] A newly-allocated pointer to a version number.
 * @param len [out] The length of \p data.
 * @returns 0 on success, or a negative errno on failure.
 */
int get_version_conn(socket_ctx* sock_ctx, int** data, unsigned int* len) {
    
    int* version = malloc(sizeof(int));
    if (version == NULL)
        return -ENOMEM;

    int openssl_version = SSL_version(sock_ctx->ssl);
    *version = tls_version_from_openssl(openssl_version);

    *data = version;
    *len = sizeof(int);

    return 0;
}


/**
 * Allocates the ID of the socket to \p out to be returned to the calling 
 * program. The socket ID can then be used in a `setsockopt()` call to 
 * have another socket use the same SSL context as this socket.
 * @param sock_ctx The context of the socket to get a TLS context from.
 * @param out A pointer to an output buffer to allocate the ID to.
 * @param len The output length of \p out.
 * @returns 0 on success, or a negative errno on failure.
 */
int get_tls_context(socket_ctx* sock_ctx, 
            unsigned long** data, unsigned int* len) {

    SSL_CTX* ssl_ctx = sock_ctx->ssl_ctx;
    unsigned long* context_id;
    int ret = 0;

    context_id = malloc(sizeof(unsigned long));
    if (data == NULL)
        goto err;

    *context_id = sock_ctx->id;

    if (session_resumption_enabled(ssl_ctx) 
                && !has_session_cache(ssl_ctx)) {
        ret = session_cache_new(ssl_ctx);
        if (ret != 0)
            goto err;
    }

    set_shared_context(sock_ctx->flags);
    *data = context_id;
    *len = sizeof(unsigned long);
    return 0;
err:
    if (data != NULL)
        free(data);
    
    return -ECANCELED;
}


/**
 * Determines whether the given socket established its current TLS handshake 
 * by resuming a former session.
 * @param sock_ctx The context of the socket to check.
 * @param data Whether the session was resumed (1) or not (0).
 * @param len The output length of \p data.
 * @returns 0 on success, or a negative errno on failure.
 */
int get_session_resumed(socket_ctx* sock_ctx, int** data, unsigned int *len) {
                
    int* is_resumed = malloc(sizeof(int));
    if (is_resumed == NULL)
        return -ECANCELED;
    
    *is_resumed = SSL_session_reused(sock_ctx->ssl);

    *data = is_resumed;
    *len = sizeof(int);

    return 0;
}


/**
 * Determines whether or not the given socket will attempt to perform session 
 * resumption on connections using cached sessions.
 * @param sock_ctx The context of the socket to check for session reuse.
 * @param data [out] Pointer to whether or not sessions are reused for this 
 * socket.
 * @param len [out] The size of \p data.
 * @returns 0 on success, or a negative errno if an error occurred.
 */
int get_session_reuse(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* reuse_sessions = malloc(sizeof(int));
    if (reuse_sessions == NULL)
        return -ECANCELED;

    *reuse_sessions = session_resumption_enabled(sock_ctx->ssl_ctx);

    *data = reuse_sessions;
    *len = sizeof(int);

    return 0;   
}


int get_revocation_checks(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* checks_enabled = malloc(sizeof(int));
    if (checks_enabled == NULL)
        return -ECANCELED;

    *checks_enabled = has_revocation_checks(sock_ctx->flags) ? 1 : 0;

    *data = checks_enabled;
    *len = sizeof(int);

    return 0;
}


int get_stapled_checks(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* checks_enabled = malloc(sizeof(int));
    if (checks_enabled == NULL)
        return -ECANCELED;

    *checks_enabled = has_stapled_checks(sock_ctx->flags) ? 1 : 0;

    *data = checks_enabled;
    *len = sizeof(int);

    return 0;
}

int get_ocsp_checks(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* checks_enabled = malloc(sizeof(int));
    if (checks_enabled == NULL)
        return -ECANCELED;

    *checks_enabled = has_ocsp_checks(sock_ctx->flags) ? 1 : 0;

    *data = checks_enabled;
    *len = sizeof(int);

    return 0;
}


int get_crl_checks(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* checks_enabled = malloc(sizeof(int));
    if (checks_enabled == NULL)
        return -ECANCELED;

    *checks_enabled = has_crl_checks(sock_ctx->flags) ? 1 : 0;

    *data = checks_enabled;
    *len = sizeof(int);

    return 0;
}


int get_cached_checks(socket_ctx* sock_ctx, int** data, unsigned int* len) {

    int* checks_enabled = malloc(sizeof(int));
    if (checks_enabled == NULL)
        return -ECANCELED;

    *checks_enabled = has_cached_checks(sock_ctx->flags) ? 1 : 0;

    *data = checks_enabled;
    *len = sizeof(int);

    return 0;
}

