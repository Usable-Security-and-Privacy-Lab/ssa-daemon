#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "error.h"
#include "getsockopt.h"
#include "in_tls.h"
#include "log.h"
#include "sessions.h"



/* setsockopt */
int get_peer_certificate(socket_ctx* sock_ctx, 
            const char** data, unsigned int* len);
int get_peer_identity(socket_ctx* sock_ctx, 
            const char** data, unsigned int* len);
int get_hostname(socket_ctx* sock_ctx, 
            const char** data, unsigned int* len);
int get_enabled_ciphers(socket_ctx* sock_ctx, 
            const char** data, unsigned int* len);
const char* get_chosen_cipher(socket_ctx* sock_ctx, unsigned int* len);
int get_tls_context(socket_ctx* sock_ctx, const char** out, unsigned int* len);
int get_session_resumed(socket_ctx* sock_ctx, 
            const char **data, unsigned int *len);


int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);


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
            int option, int* need_free, const char** data, unsigned int* len) {

    int response = 0;
    
    switch (option) {
	case TLS_ERROR:
		if (!has_error_string(sock_ctx)) {
			response = -EINVAL;
			break;
		}

		*data = sock_ctx->err_string;
		*len = strlen(sock_ctx->err_string) + 1;
		break;

	case TLS_HOSTNAME:
		if ((response = check_socket_state(sock_ctx,
				2, SOCKET_NEW, SOCKET_CONNECTED)) != 0)
			break;

		if (strlen(sock_ctx->rem_hostname) > 0) {
			*data = sock_ctx->rem_hostname;
			*len = strlen(sock_ctx->rem_hostname) + 1;
		}
		break;

	case TLS_HOSTNAME:
		if ((response = check_socket_state(sock_ctx, 
				1, SOCKET_ACCEPTED)) != 0)
			break;

		response = get_hostname(sock_ctx, data, len);
		break;

	case TLS_PEER_IDENTITY:
		if ((response = check_socket_state(sock_ctx, 2,
				SOCKET_CONNECTED, SOCKET_ACCEPTED)) != 0)
			break;

		response = get_peer_identity(sock_ctx, data, len);
		if (response == 0)
			*need_free = 1;
		break;

	case TLS_PEER_CERTIFICATE_CHAIN:
		if ((response = check_socket_state(sock_ctx, 1, SOCKET_CONNECTED)) != 0)
			break;
		response = get_peer_certificate(sock_ctx, data, len);
		if (response == 0)
			*need_free = 1;
		break;

	case TLS_TRUSTED_CIPHERS:
		response = get_enabled_ciphers(sock_ctx, data, len);
		if (response == 0)
			*need_free = 1;
		break;

    case TLS_CHOSEN_CIPHER:
        if ((response = check_socket_state(sock_ctx, 2, 
                    SOCKET_CONNECTED, SOCKET_ACCEPTED)) != 0)
            break;
        *data = get_chosen_cipher(sock_ctx, len);
        break;

    case TLS_CONTEXT:
        if ((response = check_socket_state(sock_ctx, 1, SOCKET_NEW)) != 0)
            break;
        response = get_tls_context(sock_ctx, data, len);
        if (response == 0)
            *need_free = 1;
        break;

    case TLS_RESUMED_SESSION:
        if ((response = check_socket_state(sock_ctx, 2, 
                    SOCKET_CONNECTED, SOCKET_ACCEPTED)) != 0)
            break;
        response = get_session_resumed(sock_ctx, data, len);
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
		log_printf(LOG_ERROR,
				"Default case for getsockopt hit: should never happen\n");
		response = -EBADF;
		break;
	}

    return response;
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
            const char** data, unsigned int* len) {
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
 * identity is stored in the X509 certificate that the peer had sent to us
 * in the TLS handshake.
 * @param conn The connection to retrieve peer identity information for.
 * @param identity An area to allocate the ASCII representation of the peer's
 * identity to.
 * @param len The length of identity.
 * @returns 0 on success; or -errno if an error occurred.
 */
int get_peer_identity(socket_ctx* sock_ctx, 
            const char** identity, unsigned int* len) {
	
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
int get_hostname(socket_ctx* sock_ctx, const char** data, unsigned int* len) {

	const char* hostname;

	hostname = SSL_get_servername(sock_ctx->ssl, TLSEXT_NAMETYPE_host_name);
	if (hostname == NULL) {
		set_err_string(sock_ctx, "TLS error: couldn't get the server hostname - %s",
				ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
		return -EINVAL;
	}

	*data = hostname;
	*len = strlen(hostname)+1;
	return 0;
}

/**
 * Allocates a string list of enabled ciphers to data.
 * @param conn The specified connection context to retrieve the ciphers from
 * @param data A pointer to a char pointer where the cipherlist string will be
 * allocated to, or NULL if no ciphers were available from the given connection.
 * This should be freed after use.
 * @returns 0 on success; -errno otherwise.
 */
int get_enabled_ciphers(socket_ctx* sock_ctx, 
            const char** data, unsigned int* len) {
	
	char* ciphers_str = NULL;

	STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(sock_ctx->ssl);
	/* FEATURE: use SSL_get1_supported_ciphers if connected */
	if (ciphers == NULL)
		goto end; /* no ciphers available; just return NULL. */

	int ciphers_len = get_ciphers_strlen(ciphers);
	if (ciphers_len == 0)
		goto end;

	ciphers_str = (char*) malloc(ciphers_len + 1);
	if (ciphers_str == NULL) {
		set_err_string(sock_ctx, "Daemon error: failed to allocate buffer");
		return -errno;
	}

	if (get_ciphers_string(ciphers, ciphers_str, ciphers_len + 1) != 0)
		log_printf(LOG_ERROR, "Buffer had to be truncated.\n");

	*len = ciphers_len + 1;
end:
	*data = ciphers_str;
	return 0;
}


/**
 * Returns the cipher currently in use for the connection.
 * @param sock_ctx The context of the currently connected socket to retrieve
 * cipher information from.
 * @param len The ouptut length of the cipher.
 * @returns A null-terminated string representing the cipher in current use.
 */
const char* get_chosen_cipher(socket_ctx* sock_ctx, unsigned int* len) {

    const char* data = SSL_get_cipher(sock_ctx->ssl);
    *len = strlen(data) + 1;

    return data;
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
int get_tls_context(socket_ctx* sock_ctx, const char** out, unsigned int* len) {

    SSL_CTX* ssl_ctx = sock_ctx->ssl_ctx;
    uint64_t id = sock_ctx->id;
    char* data = NULL;
    int ret = 0;

    log_printf(LOG_DEBUG, "ID being got: %lu\n", id);

    data = malloc(sizeof(id));
    if (data == NULL)
        goto err;

    memcpy(data, &id, sizeof(id));

    if (client_session_resumption_enabled(ssl_ctx) 
                && !has_session_cache(ssl_ctx)) {
        ret = session_cache_new(ssl_ctx);
        if (ret != 0)
            goto err;
    }

    *out = data;
    *len = sizeof(id);
    return 0;
err:
    if (data != NULL)
        free(data);
    
    return -ECANCELED;
}

int get_session_resumed(socket_ctx* sock_ctx, 
            const char **data, unsigned int *len) {
                
    char* tmp = malloc(sizeof(int));
    if (tmp == NULL)
        return -ECANCELED;
    
    int is_reused = SSL_session_reused(sock_ctx->ssl);

    memcpy(tmp, &is_reused, sizeof(int));
    *data = tmp;
    *len = sizeof(int);
    return 0;
}


/*
 *******************************************************************************
 *                             HELPER FUNCTIONS
 *******************************************************************************
 */


/**
 * Converts a stack of SSL_CIPHER objects into a single string representation
 * of all the ciphers, with each individual cipher separated by a ':'.
 * @param ciphers The stack of ciphers to convert
 * @param buf the provided buffer to put the string into.
 * @param buf_len The length of the provided buffer.
 * @returns 0 on success; -1 if the buffer was not big enough to store all of
 * the ciphers and had to be truncated.
 */
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len) {
	int index = 0;
	for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER* curr = sk_SSL_CIPHER_value(ciphers, i);
		const char* cipher = SSL_CIPHER_get_name(curr);

		if ((index + strlen(cipher) + 1) > buf_len) {
			buf[index-1] = '\0';
			return -1; /* buf not big enough */
		}

		strcpy(&buf[index], cipher);
		index += strlen(cipher);
		buf[index] = ':';
		index += 1;
	}
	buf[index - 1] = '\0'; /* change last ':' to '\0' */
	return 0;
}

/**
 * Determines the combined string length of all the cipher strings.
 * @param ciphers The cipher list to measure string lengths from.
 * @returns The combined string length of the ciphers in the list (as if
 * there were ':' characters between each cipher and a terminating
 * '\0' at the end). Never returns an error code.
 */
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers) {
	int len = 0;
	for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const char* curr = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
		len += strlen(curr) + 1; /* add ':' */
	}
	if (len != 0)
		len -= 1; /* removes the last ':' */
	return len;
}