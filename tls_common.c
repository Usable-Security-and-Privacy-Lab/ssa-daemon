#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "tls_server.h"

#include <string.h>

#include <openssl/err.h>

int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);



/**
 * Meant to be called after a general OpenSSL function fails; takes the set
 * OpenSSL error code in the error queue and associates it with the current
 * socket
 */
void set_sock_tls_error(sock_context* sock_ctx) {
	unsigned long ssl_err = ERR_get_error();

	if (ssl_err == 0) {
		log_printf(LOG_ERROR, "Error occurred but not captured by OpenSSL\n");
		sock_ctx->error_code = 0;
	}

	/* TODO: finish */
}



void set_tls_connection_error(sock_context* sock_ctx) {
	/* TODO: stub */
}




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
int get_peer_certificate(connection* conn, char** data, unsigned int* len) {
	X509* cert = NULL;
	BIO* bio = NULL;
	char* bio_data = NULL;
	char* pem_data = NULL;
	unsigned int cert_len;
	int ret;

	cert = SSL_get_peer_certificate(conn->tls);
	if (cert == NULL) {
		/* TODO: get specific error from OpenSSL */
		ret = -ENOTCONN;
		goto end;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		/* TODO: get specific error from OpenSSL */
		ret = -ENOMEM;
		goto end;
	}

	if (PEM_write_bio_X509(bio, cert) == 0) {
		/* TODO: get specific error from OpenSSL */
		ret = -ENOTSUP;
		goto end;
	}

	cert_len = BIO_get_mem_data(bio, &bio_data);
	pem_data = malloc(cert_len + 1); /* +1 for null terminator */
	if (pem_data == NULL) {
		ret = -errno;
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

int get_peer_identity(connection* conn_ctx, char** data, unsigned int* len) {
	X509* cert;
	X509_NAME* subject_name;
	char* identity;
	if (conn_ctx->tls == NULL)
		return 0;
	cert = SSL_get_peer_certificate(conn_ctx->tls);
	if (cert == NULL) {
		log_printf(LOG_INFO, "peer cert is NULL\n");
		return 0;
	}
	subject_name = X509_get_subject_name(cert);
	identity = X509_NAME_oneline(subject_name, NULL, 0);
	*data = identity;
	*len = strlen(identity)+1;
	return 1;
}

int get_hostname(connection* conn_ctx, char** data, unsigned int* len) {
	const char* hostname;
	if (conn_ctx == NULL) {
		return 0;
	}
	hostname = SSL_get_servername(conn_ctx->tls, TLSEXT_NAMETYPE_host_name);
	*data = (char*)hostname;
	if (hostname == NULL) {
		*len = 0;
		return 1;
	}
	*len = strlen(hostname)+1;
	return 1;
}

/**
 * Allocates a string list of enabled ciphers to data.
 * @param conn The specified connection context to retrieve the ciphers from
 * @param data A pointer to a char pointer where the cipherlist string will be
 * allocated to, or NULL if no ciphers were available from the given connection.
 * This should be freed after use.
 * @returns 0 on success; -errno otherwise.
 */
int get_enabled_ciphers(connection* conn, char** data, unsigned int* len) {
	char* ciphers_str = "";




	STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(conn->tls);
	/* TODO: replace this with SSL_get1_supported_ciphers? Maybe... */
	if (ciphers == NULL)
		goto end; /* no ciphers available; just return NULL. */

	int ciphers_len = get_ciphers_strlen(ciphers);
	if (ciphers_len == 0)
		goto end;

	ciphers_str = (char*) malloc(ciphers_len + 1);
	if (ciphers_str == NULL)
		return -errno;

	if (get_ciphers_string(ciphers, ciphers_str, ciphers_len + 1) != 0) {
		log_printf(LOG_ERROR, "Buffer wasn't big enough; had to be truncated.\n");
	}

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

int set_connection_type(connection* conn, daemon_context* daemon, int type) {

	int ret;

	switch(conn->state) {
	case CLIENT_NEW:
	case SERVER_NEW:
		break; /* Socket in good state */
	default:
		return -ENOPROTOOPT;
	}

	if (type == CLIENT_CONN)
		ret = client_SSL_new(conn, daemon);
	else /* type == SERVER_CONN */
		ret = server_SSL_new(conn, daemon);

	if (ret != 0)
		conn->state = CONN_ERROR;
	else
		conn->state = (type == CLIENT_CONN) ? CLIENT_NEW : SERVER_NEW;

	return ret;
}

/* TODO: Test this */
int set_trusted_peer_certificates(connection* conn, char* value) {
	/* XXX update this to take in-memory PEM chains as well as file names */
	/* ^ old comment, maybe still do? */

	if (conn == NULL)
		return 0;

	STACK_OF(X509_NAME)* cert_names = SSL_load_client_CA_file(value);
	if (cert_names == NULL)
		return 0;

	SSL_set_client_CA_list(conn->tls, cert_names);
	return 1;
}

/**
 * Removes a given cipher from the set of enabled ciphers for a connection.
 * TODO: Allow multiple ciphers to be disabled at the same time?
 * @param conn The connection context to remove a cipher from.
 * @param cipher A string representation of the cipher to be removed.
 * @returns 0 on success; -errno otherwise. EINVAL means the cipher to be
 * removed was not found.
 */
int disable_cipher(connection* conn, char* cipher) {

	STACK_OF(SSL_CIPHER)* cipherlist = SSL_get_ciphers(conn->tls);
	if (cipherlist == NULL)
		return -EINVAL;

	int ret = clear_from_cipherlist(cipher, cipherlist);
	if (ret != 0)
		return -EINVAL;

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
