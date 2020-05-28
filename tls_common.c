#include "config.h"
#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "tls_server.h"

#include <fcntl.h> /* for S_IFDIR/S_IFREG constants */
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>

#define UBUNTU_DEFAULT_CA "/etc/ssl/certs/ca-certificates.crt"
#define FEDORA_DEFAULT_CA "/etc/pki/tls/certs/ca-bundle.crt"


int concat_ciphers(char** list, int num, char** out);

int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);
int check_key_cert_pair(SSL* tls);


/**
 *******************************************************************************
 *                           COMMON CONFIG LOADING FUNCTIONS
 *******************************************************************************
 */

/**
 * Converts the given tls_version_t enum into the OpenSSL-specific version.
 * @param version The version given to us by the config file.
 * @returns The OpenSSL representation of the TLS Version, or TLS1_2_VERSION
 * if no version was set (a safe default).
 */
long get_tls_version(enum tls_version_t version) {

	long tls_version = 0;

	switch(version) {
	case TLS_DEFAULT_ENUM:
		tls_version = TLS_MAX_VERSION;
		break;
	case TLS1_0_ENUM:
		tls_version = TLS1_VERSION;
		break;
	case TLS1_1_ENUM:
		tls_version = TLS1_1_VERSION;
		break;
	case TLS1_2_ENUM:
		tls_version = TLS1_2_VERSION;
		break;
	case TLS1_3_ENUM:
		tls_version = TLS1_3_VERSION;
		break;
	default:
		/* shouldn't happen */
		log_printf(LOG_ERROR, "Unknown TLS version specified\n");
	}

	return tls_version;
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
		log_printf(LOG_ERROR, "Some cipher names were not recognized\n");
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
		log_printf(LOG_ERROR, "Some cipher names were not recognized\n");
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
		log_printf(LOG_ERROR, "Malloc failed while loading cipher list: %s\n",
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
		log_printf(LOG_DEBUG, "load_cipher_list had unexpected results\n");
		free(ciphers);
		return 0;
	}

	*out = ciphers;
	return 1;
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

	if (CA_path == NULL) { /* No CA file given--search for one based on system */
		if (access(UBUNTU_DEFAULT_CA, F_OK) != -1) {
			CA_path = UBUNTU_DEFAULT_CA;
			log_printf(LOG_INFO, "Found the Ubuntu CA file.\n");
		
		} else if(access(FEDORA_DEFAULT_CA, F_OK) != -1) {
			CA_path = FEDORA_DEFAULT_CA;
			log_printf(LOG_INFO, "Found the Fedora CA file.\n");
		
		} else { /* UNSUPPORTED OS */
			log_printf(LOG_ERROR, "Unable to find valid CA location.\n");
			return 0;
		}
	}

	
	if (stat(CA_path, &file_stats) != 0) {
		log_printf(LOG_ERROR, "Failed to access CA file %s: %s\n", 
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
		log_printf(LOG_ERROR, "Loading CA certs--path not file or directory\n");
		return 0;
	}
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
int get_peer_identity(connection* conn, char** identity, unsigned int* len) {
	
	X509_NAME* subject_name;
	X509* cert;

	if (conn->tls == NULL)
		return -ENOTCONN;

	cert = SSL_get_peer_certificate(conn->tls);
	if (cert == NULL)
		return -ENOTCONN;

	subject_name = X509_get_subject_name(cert); /* internal ptr; don't free */
	*identity = X509_NAME_oneline(subject_name, NULL, 0);
	if (*identity == NULL) {
		X509_free(cert);
		return ssl_malloc_err(conn);
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
int get_hostname(connection* conn, char** data, unsigned int* len) {

	const char* hostname;
	
	switch (conn->state) {
	case SERVER_NEW:
	case SERVER_CONNECTING:
	case SERVER_CONNECTED:
		break;
	default:
		return -EINVAL;
	}

	hostname = SSL_get_servername(conn->tls, TLSEXT_NAMETYPE_host_name);
	if (hostname == NULL)
		return -EINVAL;

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

/**
 * Configures the given connection to be a client connection.
 * @param conn The connection whose state should be modified.
 * @param daemon The daemon's context.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_connection_client(connection* conn, daemon_context* daemon) {

	int ret = client_SSL_new(conn, daemon);
	if (ret == 0)
		conn->state = CLIENT_NEW;

	return ret;
}

/**
 * Configures the given connection to be a server connection.
 * @param conn The connection whose state should be modified.
 * @param daemon The daemon's context.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_connection_server(connection* conn, daemon_context* daemon) {

	int ret = server_SSL_new(conn, daemon);
	if (ret == 0)
		conn->state = SERVER_NEW;

	return ret;
}

/**
 * Sets the certificate chain to be used for a given connection conn using
 * the file/directory pointed to by path. 
 * @param conn The connection to load the certificate chain into.
 * @param path The path to the certificate chain directory/file.
 * @returns 0 on success, or -errno if an error occurred.
 */
int set_certificate_chain(connection* conn, char* path) {

	struct stat file_stats;
	int ret;

	ret = stat(path, &file_stats);
	if (ret != 0) {
		ret = -errno;
		goto err;
	}

	if (S_ISREG(file_stats.st_mode)) {
		/* is a file */
		ret = SSL_use_certificate_chain_file(conn->tls, path);
		if (ret != 1) {
			log_printf(LOG_ERROR, "Failed to load cert chain\n");
			/* TODO: set errno to SSL error */
			ret = -EBADF;
			goto err;
		}

	} else if (S_ISDIR(file_stats.st_mode)) {
		/* is a directory */
		/* TODO: add functionality for reading from folder.
		 * See man fts for functions needed to do this */

		/* stub */
		ret = -EBADF;
		goto err;
	} else {
		/* could be a link, a socket, etc */
		ret = -EBADF;
		goto err;
	}

	return 0;
 err:
	log_printf(LOG_ERROR, "Failed to set cert chain: %i\n", ret);
	return ret;
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
int set_private_key(connection* conn, char* path) {

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

	ret = SSL_use_PrivateKey_file(conn->tls, path, SSL_FILETYPE_PEM);
	if (ret == 1) /* pem key loaded */
		return check_key_cert_pair(conn->tls); 
	else
		ERR_clear_error();

	ret = SSL_use_PrivateKey_file(conn->tls, path, SSL_FILETYPE_ASN1);
	if (ret == 1) /* ASN.1 key loaded */
		return check_key_cert_pair(conn->tls);  
	else
		ERR_clear_error();

	ret = SSL_use_PrivateKey_file(conn->tls, path, SSL_FILETYPE_PEM);
	if (ret == 1) /* pem RSA key loaded */
		return check_key_cert_pair(conn->tls); 
	else
		ERR_clear_error();

	ret = SSL_use_RSAPrivateKey_file(conn->tls, path, SSL_FILETYPE_ASN1);
	if (ret == 1) /* ASN.1 RSA key loaded */
		return check_key_cert_pair(conn->tls); 
	
	/* TODO: set ret to OpenSSL error */
	ret = -EBADF;
 err:
	log_printf(LOG_ERROR, "Failed to set private key: %i\n", ret);
	return ret;
}

/**
 * Sets the trusted Certificate Authority certificates for the given
 * connection conn to those found in the file specified by path.
 * @param conn The connection to modify CA trusts on.
 * @param path The path to a file containing .pem encoded CA's.
 * @returns 0 on success, or -ernno if an error occurred. 
 */
int set_trusted_CA_certificates(connection* conn, char* path) {
	
	STACK_OF(X509_NAME)* cert_names = SSL_load_client_CA_file(path);
	if (cert_names == NULL)
		return -EBADF;

	SSL_set_client_CA_list(conn->tls, cert_names);

	return 0;
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

/** 
 * Verifies that the loaded private key and certificate match each other.
 * @pre The Private Key and Certificate chain have already been loaded into
 * tls.
 * @param tls The SSL object containing the certificate chain and private key
 * for which to check.
 * @returns 0 if the checks succeeded; -EPROTO otherwise. 
 */
int check_key_cert_pair(SSL* tls) {
	if (SSL_check_private_key(tls) != 1) {
		log_printf(LOG_ERROR, "Key and certificate don't match.\n");
		goto err;
	}

	if (SSL_build_cert_chain(tls, SSL_BUILD_CHAIN_FLAG_CHECK) != 1) {
		log_printf(LOG_ERROR, "Certificate chain failed to build.\n");
		goto err;
	}

	return 0;
 err:
	return -EPROTO; /* Protocol err--key didn't match or chain didn't build */
}