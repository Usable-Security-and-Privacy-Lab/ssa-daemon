#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "bev_callbacks.h"
#include "config.h"
#include "daemon_structs.h"
#include "log.h"
#include "tls_server.h"


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

SSL_CTX* server_ctx_init_default();

/**
 * Initializes the server SSL_CTX to safe and rigorous defaults.
 * @returns A pointer to an SSL_CTX, or NULL on failure.
 */
SSL_CTX* server_ctx_init_default() {

	int ret = 0;

	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL)
		goto err;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	if (ret != 1)
		goto err;

	ret = SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	if (ret != 1)
		goto err;

	ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	if (ret != 1)
		goto err;

	ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	if (ret != 1)
		goto err;

	ret = SSL_CTX_load_verify_locations(ctx, DEBUG_TEST_CA, NULL);
	if (ret != 1)
		goto err;

	/* TODO: WARNING: temporary--for debugging. Remove for prod */
	
	ret = SSL_CTX_use_certificate_chain_file(ctx, DEBUG_CERT_CHAIN);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_use_PrivateKey_file(ctx, DEBUG_PRIVATE_KEY, SSL_FILETYPE_PEM);
	if (ret != 1)
		goto err;

	ret = SSL_CTX_check_private_key(ctx);
	if (ret != 1) {
		log_printf(LOG_ERROR, "Loaded Private Key didn't match cert chain\n");
		goto err;
	}

	ret = SSL_CTX_build_cert_chain(ctx, SSL_BUILD_CHAIN_FLAG_CHECK);
	if (ret != 1) {
		log_printf(LOG_ERROR, "Incomplete server certificate chain\n");
		goto err;
	}

	/* endof TODO/WARNING */

	return ctx;
 err:
	if (ERR_peek_error())
		log_printf(LOG_ERROR, "OpenSSL error initializing server SSL_CTX: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	
	if (ctx != NULL)
		SSL_CTX_free(ctx);

    return NULL;
}


int load_certificates(SSL_CTX* ctx, char** cert_chain, int cert_cnt);

SSL_CTX* server_ctx_init(server_settings* config) {

	SSL_CTX* ctx = NULL;
	long tls_version;
	int ret;

	if (config == NULL)
		return server_ctx_init_default();
	
	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL)
		goto err;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	

	if (!config->tls_compression)
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	/* TODO: test to see that both options are set */
	if (!config->session_tickets)
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);


	tls_version = get_tls_version(config->min_tls_version);
	if (SSL_CTX_set_min_proto_version(ctx, tls_version) != 1)
		goto err;

	tls_version = get_tls_version(config->max_tls_version);
	if (SSL_CTX_set_max_proto_version(ctx, tls_version) != 1)
		goto err;


	if (config->cipher_list_cnt != 0) {
		ret = load_cipher_list(ctx,
				config->cipher_list, config->cipher_list_cnt);
	} else {
		ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	}
	if (ret != 1)
		goto err;
	

	if (config->ciphersuite_cnt != 0) {
		ret = load_ciphersuites(ctx, 
				config->ciphersuites, config->ciphersuite_cnt);
	} else {
		ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	}
	if (ret != 1)
		goto err;

	/* TODO: WARNING: temporary--for debugging. Remove for prod */
	
	ret = load_certificates(ctx, config->certificates, config->cert_cnt); 
	if (ret != 1) {
		log_printf(LOG_ERROR, "Couldn't load certificates\n");
		goto err;
	}

	ret = SSL_CTX_use_PrivateKey_file(ctx, config->private_keys[0], SSL_FILETYPE_PEM); // FIXME (multiple keys)
	if (ret != 1) {
		log_printf(LOG_ERROR, "Incorrect private key file\n");
		goto err;
	}

	ret = SSL_CTX_check_private_key(ctx);
	if (ret != 1) {
		log_printf(LOG_ERROR, "Loaded Private Key didn't match cert chain\n");
		goto err;
	}

	ret = SSL_CTX_build_cert_chain(ctx, SSL_BUILD_CHAIN_FLAG_CHECK);
	if (ret != 1) {
		log_printf(LOG_ERROR, "Incomplete server certificate chain\n");
		goto err;
	}

	SSL_CTX_set_timeout(ctx, config->session_timeout);

	/* endof TODO/WARNING */

	return ctx;
 err:
	log_printf(LOG_ERROR, "OpenSSL error initializing server SSL_CTX: %s\n", 
			ERR_error_string(ERR_get_error(), NULL));
	
	if (ctx != NULL)
		SSL_CTX_free(ctx);
    return NULL;
}



/**
 * Allocates a new SSL struct set with the daemon's set server settings.
 * On failure, the old SSL struct is preserved in the connection.
 */
int server_SSL_new(connection* conn, daemon_context* daemon) {
	
	SSL* temp = SSL_new(daemon->server_ctx);
	if (temp == NULL)
		return ssl_malloc_err(conn);
	
	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = temp;

	return 0;
}

int accept_SSL_new(connection* conn, connection* old) {
	if (conn->tls != NULL) 
		SSL_free(conn->tls);

	conn->tls = SSL_dup(old->tls);
	if (conn->tls == NULL)
		return ssl_malloc_err(old);
	else
		return 0;
}

/**
 * If the last 4 chars of a string are ".pem" return 1, else return 0.
 */
int is_pem_file(char* path) {
	int len = strlen(path);
	int pem_len = 4;
	char* type = &path[len - pem_len];

	if(strcmp(type, ".pem") == 0) 
		return 1;
	else
		return 0;
}

/*
 * Searches cert_list for a self-signed (root) certificate. Returns index of the root 
 * certificate in cert_list or -1 if the root CA or the X509 extension is not found.
 */
int get_root_cert(X509** cert_list, int num_certs) {
	for(int j = 0; j < num_certs; ++j) {
		const ASN1_STRING* subject = X509_get0_subject_key_id(cert_list[j]); 
		if(subject == NULL) 
			return -1;
		
   		const ASN1_STRING* issuer = X509_get0_authority_key_id(cert_list[j]);
		if(issuer == NULL) 
			return -1;
		
		if(ASN1_STRING_cmp(subject, issuer) == 0) 
			return j;		
	}
	return -1;
}

/*
 * Starting with the root CA, searches cert_list for the last certificate in the chain.
 * Returns the index of the end cert or -1 on error.
 */
int get_end_entity(X509** cert_list, int num_certs) {
	int root_index = get_root_cert(cert_list, num_certs);
	if(root_index < 0) {
		log_printf(LOG_ERROR, "Could not locate root certificate.\n");
		return -1;
	}

	int end_entity_index = 0;
	const ASN1_STRING* ca = X509_get0_subject_key_id(cert_list[root_index]);

	for(int index = 1; index < num_certs; ++index) {
		for(int j = 0; j < num_certs; ++j) {

			if(j == root_index)
				continue;
			
			const ASN1_STRING* issuer = X509_get0_authority_key_id(cert_list[j]);
			if(ASN1_STRING_cmp(issuer, ca) == 0) {
				end_entity_index = j;
				ca = X509_get0_subject_key_id(cert_list[j]);
				break;
			}

			if(j == num_certs - 1) {
				log_printf(LOG_ERROR, "Files in directory do not make a complete chain.\n");
				return -1;
			}
		}
	}
	return end_entity_index;
}

int get_directory_certs(X509** cert_list, DIR* directory, char* dir_name) {
	struct dirent* in_file;
	int num_certs = 0; 
	int max_file_name_len = 128;
	char file_name[max_file_name_len];

	while ((in_file = readdir(directory))) {

		if (!strcmp (in_file->d_name, ".")) 
            continue;

        if (!strcmp (in_file->d_name, ".."))    
            continue;

		char* cert_name = in_file->d_name;
		printf("%s\n", cert_name); // for debugging

		file_name[0] = 0;
		sprintf(file_name, "%s/%s", dir_name, cert_name);
		FILE* current_file = fopen(file_name, "r"); 

		if(current_file == NULL) {
			log_printf(LOG_ERROR, "Error: Could not open file %s (Errno %d).\n", file_name, errno);
			return -1;
		}
		
		if(is_pem_file(file_name)) {
			cert_list[num_certs] = PEM_read_X509(current_file, NULL, 0, NULL);
		}

		else { // test this (DER file)
			cert_list[num_certs] = d2i_X509_fp(current_file, NULL);
		}

		if(cert_list[num_certs] == NULL) {
			log_printf(LOG_ERROR, "Error converting \"%s\" file to certificate.\n", cert_name);
			return -1;
		}
		
		++num_certs;
		errno = 0;
	}
	if(errno != 0) {
		log_printf(LOG_ERROR, "Error reading directory %s.\n", dir_name);
		return -1;
	}
	return num_certs;
}

// If this works, remove comment in config file to sort directory
int add_directory_certs(SSL_CTX* ctx, X509** cert_list, int num_certs) { 
	int end_index = get_end_entity(cert_list, num_certs);
	if(end_index < 0) {
		log_printf(LOG_ERROR, "Could not locate end entity certificate.\n");
		return 0;
	}

	if(SSL_CTX_use_certificate(ctx, cert_list[end_index]) != 1) {
		log_printf(LOG_ERROR, "Error loading end certificate.\n");
		return 0;
	}

	const ASN1_STRING* issuer = X509_get0_authority_key_id(cert_list[end_index]);
	for(int j = 1; j < num_certs; ++j) {
		for(int k = 0; k < num_certs; ++k) {
			const ASN1_STRING* subject = X509_get0_subject_key_id(cert_list[k]);
			if(ASN1_STRING_cmp(issuer, subject) == 0) {
				if(SSL_CTX_add0_chain_cert(ctx, cert_list[k]) != 1) { 
					log_printf(LOG_ERROR, "Error adding CA to chain.\n");
					return 0;
				}
				issuer = X509_get0_authority_key_id(cert_list[k]);
				break;
			}
		}
	}

	return 1;
}

/**
 * Load all certificates into ctx. 
 * Returns 1 on success, 0 on error.
 */
int load_certificates(SSL_CTX* ctx, char** cert_chain, int cert_cnt) { 
	
	// for(int i = 0; i < cert_cnt; ++i) // add all cert chains? distinguish somehow?

	if(is_pem_file(cert_chain[0])) {
		return SSL_CTX_use_certificate_chain_file(ctx, cert_chain[0]);
	}

	char* dir_name = cert_chain[0];
	DIR* directory = opendir(dir_name);
	if(directory != NULL) {
		int max_certs = 5; // get from config file
		X509* cert_list[max_certs];
		int num_certs = get_directory_certs(cert_list, directory, dir_name);
		return add_directory_certs(ctx, cert_list, num_certs); 
	}
	else {
		log_printf(LOG_ERROR, "Error: Could not open directory.\n");
	}

	log_printf(LOG_ERROR, "[cert-path] must be a pem file or directory.\n");
	return 0;
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
	int ret;

	accept_conn->addr = internal_addr;
	accept_conn->addrlen = internal_addrlen;

	accept_conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base, 
			new_sock->fd, new_sock->conn->tls, BUFFEREVENT_SSL_ACCEPTING, 0);
	if (accept_conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Client bev setup failed [listener]\n");
		goto err;
	}
	
	bufferevent_setcb(accept_conn->secure.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(accept_conn->secure.bev, 1);
	#endif
	
	/* This will still result in a CONNECTED event--TLS also has to connect */
	ret = bufferevent_enable(accept_conn->secure.bev, EV_READ | EV_WRITE);
	if (ret != 0) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Secure bev enable failed [listener]\n");
		goto err;
	}

	/* Should be the last error-prone function to be called, so that on errror
	 * ifd doesn't get closed twice by the calling function */
	accept_conn->plain.bev = bufferevent_socket_new(daemon->ev_base, 
			ifd, BEV_OPT_CLOSE_ON_FREE);
	if (accept_conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Server bev setup failed [listener]\n");
		goto err;
	}

	bufferevent_setcb(accept_conn->plain.bev, common_bev_read_cb, 
			common_bev_write_cb, server_bev_event_cb, new_sock);

    return 0;
err:
	/* closing/freeing is left up to the calling function */
    return ret;
}



/*******************************************************************************
 *                      SETSOCKOPT FUNCTIONS
 ******************************************************************************/

/**
 *
 * 
 */
int set_remote_hostname(connection* conn, char* hostname) {

	SSL_set_tlsext_host_name(conn->tls, hostname);
	
	if (SSL_set1_host(conn->tls, hostname) != 1) {
		set_err_string(conn, "TLS error: unable to set hostname - %s", 
				ERR_reason_error_string(ERR_GET_REASON(ERR_get_error())));
		return -EINVAL;
	}

	return 0;
}
