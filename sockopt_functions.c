#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "error.h"
#include "log.h"
#include "sockopt_functions.h"


int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int check_key_cert_pair(socket_ctx* sock_ctx);

/*
 *******************************************************************************
 *                            GETSOCKOPT FUNCTIONS
 *******************************************************************************
 */

/**
 * Retrieves the peer's certificate (if such exists) and allocates data to a
 * PEM-formatted string representing that certificate.
 * @param conn The connection context to retrieve a peer certificate from.
 * @param data A memory address for the certificate string to be allocated to.
 * @param len The string length of the certificate.
 * @returns 0 on success; -errno otherwise.
 */
int get_peer_certificate(socket_ctx* sock_ctx, char** data, unsigned int* len) {
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
		/* TODO: get specific error from OpenSSL */
		ret = determine_and_set_error(sock_ctx);
		goto end;
	}

	if (PEM_write_bio_X509(bio, cert) == 0) {
		/* TODO: get specific error from OpenSSL */
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
int get_peer_identity(socket_ctx* sock_ctx, char** identity, unsigned int* len) {
	
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

	const char* hostname;

	hostname = SSL_get_servername(sock_ctx->ssl, TLSEXT_NAMETYPE_host_name);
	if (hostname == NULL) {
		set_err_string(sock_ctx, "TLS error: couldn't get the server hostname - %s",
				ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
		return -EINVAL;
	}

	*data = (char*)hostname;
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
int get_enabled_ciphers(socket_ctx* sock_ctx, char** data, unsigned int* len) {
	
	char* ciphers_str = NULL;

	STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(sock_ctx->ssl);
	/* TODO: FEATURE: use SSL_get1_supported_ciphers if connected */
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
	log_printf(LOG_DEBUG, "Trusted ciphers:\n%s\n", ciphers_str);
	log_printf(LOG_DEBUG, "Cipher length: %i\n", *len);
	*data = ciphers_str;
	return 0;
}

/*
 *******************************************************************************
 *                           SETSOCKOPT FUNCTIONS
 *******************************************************************************
 */


/**
 * Sets the certificate chain to be used for a given connection conn using
 * the file/directory pointed to by path. 
 * @param conn The connection to load the certificate chain into.
 * @param path The path to the certificate chain directory/file.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_certificate_chain(socket_ctx* sock_ctx, char* path) {

	struct stat file_stats;
	int ret, response, ssl_err;

	ret = stat(path, &file_stats);
	if (ret != 0) {
		response = -errno;
		goto err;
	}

	if (S_ISREG(file_stats.st_mode)) {
		/* is a file */
		ret = SSL_CTX_use_certificate_chain_file(sock_ctx->ssl_ctx, path);
		if (ret != 1) {
			response = -EBADF;
			goto err;
		}

	} else if (S_ISDIR(file_stats.st_mode)) {
		/* is a directory */
		/* TODO: add functionality for reading from folder.
		 * See man fts for functions needed to do this */

		/* stub */
		response = -EBADF;
		goto err;
	} else {
		/* could be a link, a socket, etc */
		response = -EBADF;
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
 * 
 * @param conn The connection to add the given private key to.
 * @param path The location of the Private Key file.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_private_key(socket_ctx* sock_ctx, char* path) {

	struct stat file_stats;
	int ret;

	ret = stat(path, &file_stats);
	if (ret != 0) {
		ret = -errno;
		goto err;
	}
	if (!S_ISREG(file_stats.st_mode)) {
		ret = -EBADF;
		goto err;
	}

	ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, path, SSL_FILETYPE_PEM);
	if (ret == 1) /* pem key loaded */
		return check_key_cert_pair(sock_ctx); 
	else
		clear_global_errors();

	ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, path, SSL_FILETYPE_ASN1);
	if (ret == 1) /* ASN.1 key loaded */
		return check_key_cert_pair(sock_ctx);  
	else
		clear_global_errors();

	ret = SSL_CTX_use_PrivateKey_file(sock_ctx->ssl_ctx, path, SSL_FILETYPE_PEM);
	if (ret == 1) /* pem RSA key loaded */
		return check_key_cert_pair(sock_ctx); 
	else
		clear_global_errors();

	ret = SSL_CTX_use_RSAPrivateKey_file(sock_ctx->ssl_ctx, path, SSL_FILETYPE_ASN1);
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

/**
 * Sets the trusted Certificate Authority certificates for the given
 * connection conn to those found in the file specified by path.
 * @param conn The connection to modify CA trusts on.
 * @param path The path to a file containing .pem encoded CA's.
 * @returns 0 on success, or -ernno if an error occurred. 
 */
int set_trusted_CA_certificates(socket_ctx *sock_ctx, char* path) {
	
	STACK_OF(X509_NAME)* cert_names = SSL_load_client_CA_file(path);
	if (cert_names == NULL) {
		set_err_string(sock_ctx, "TLS error: unable to load CA certificates - %s",
				ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
		return -EBADF;
	}

	SSL_CTX_set_client_CA_list(sock_ctx->ssl_ctx, cert_names);

	return 0;
}

/**
 * Removes a given cipher from the set of enabled ciphers for a connection.
 * TODO: Allow multiple ciphers to be disabled at the same time?
 * @param sock_ctx The socket context to remove a cipher from.
 * @param cipher A string representation of the cipher to be removed.
 * @returns 0 on success; -errno otherwise. EINVAL means the cipher to be
 * removed was not found.
 */
int disable_cipher(socket_ctx* sock_ctx, char* cipher) {

	STACK_OF(SSL_CIPHER)* cipherlist = SSL_CTX_get_ciphers(sock_ctx->ssl_ctx);
	if (cipherlist == NULL)
		goto err;

	int ret = clear_from_cipherlist(cipher, cipherlist);
	if (ret != 0)
		goto err;

	return 0;
 err:
	set_err_string(sock_ctx, "TLS error: cipher already disabled");
	return -EINVAL;
}


/**
 *
 * 
 */
int set_remote_hostname(socket_ctx* sock_ctx, char* hostname, long len) {

    if (len > MAX_HOSTNAME || len <= 0)
        return -EINVAL;

    memcpy(sock_ctx->rem_hostname, hostname, len);

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


