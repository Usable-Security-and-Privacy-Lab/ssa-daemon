#include <errno.h>
#include <string.h>

#include <unistd.h> //added to use the `access()` function call.


#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "config.h"
#include "log.h"
#include "tls_client.h"
#include "tls_common.h"
#include "daemon_structs.h"
#include "bev_callbacks.h"


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




SSL_CTX* client_ctx_init_default();

int launch_ocsp_checks(sock_context* sock_ctx, char** urls, int num_urls);
int launch_crl_checks(sock_context* sock_ctx, char** urls, int num_urls);



/**
 * Allocates a new SSL_CTX struct and loads the settings found in config into
 * it. If config is NULL, then secure default settings are loaded using
 * client_ctx_init_default().
 * @param config The configuration settings to have applied to the given
 * client SSL_CTX.
 * @returns A pointer to a newly allocated and set SSL_CTX, or NULL on error.
 */
SSL_CTX* client_ctx_init(client_settings* config) {

	SSL_CTX* ctx = NULL;
	long tls_version;
	int ret;

	if (config == NULL)
		return client_ctx_init_default();

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		goto err;


	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	if (!config->tls_compression)
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	tls_version = get_tls_version(config->min_tls_version);
	if (SSL_CTX_set_min_proto_version(ctx, tls_version) != 1) 
		goto err;

	tls_version = get_tls_version(config->max_tls_version);
	if (SSL_CTX_set_max_proto_version(ctx, tls_version) != 1)
		goto err;


	if (config->cipher_list_cnt > 0) {
		ret = load_cipher_list(ctx, 
				config->cipher_list, config->cipher_list_cnt);
	} else {
		ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	}
	if (ret != 1)
		goto err;
	

	if (config->ciphersuite_cnt > 0) {
		ret = load_ciphersuites(ctx, 
				config->ciphersuites, config->ciphersuite_cnt);
	} else {
		ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	}
	if (ret != 1)
		goto err;

	ret = load_certificate_authority(ctx, config->ca_path);
	if (ret != 1)
		goto err;

    /* TODO: if (!config->no_ocsp_stapling) */
	SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);



	SSL_CTX_set_timeout(ctx, config->session_timeout);
	SSL_CTX_set_verify_depth(ctx, config->max_cert_chain_depth);

	return ctx;
 err:
	if (ERR_peek_error())
		log_printf(LOG_ERROR, "OpenSSL error initializing client SSL_CTX: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	
	if (ctx != NULL)
		SSL_CTX_free(ctx);
    return NULL;
}

/**
 * Creates a new client SSL_CTX with secure default settings applied to it.
 * @returns A pointer to a newly allocated SSL_CTX set with secure settings, or
 * NULL on failure.
 */
SSL_CTX* client_ctx_init_default() {

	int ret;

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		goto err;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION 
			| SSL_OP_NO_TICKET);

	ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_max_proto_version(ctx, TLS_MAX_VERSION);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_ciphersuites(ctx, DEFAULT_CIPHERSUITES);
	if (ret != 1)
		goto err;
	
	ret = SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
	if (ret != 1)
		goto err;

	ret = load_certificate_authority(ctx, NULL);
	if (ret != 1)
		goto err;

	SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);

	return ctx;
 err:
	if (ctx != NULL)
		SSL_CTX_free(ctx);

	if (ERR_peek_error() != 0)
		log_printf(LOG_ERROR, "OpenSSL error initializing client SSL_CTX: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	return NULL;
}


/**
 * Attempts to create a new SSL struct and attach it to the given connection.
 * If unsuccessful, the connection's state will not be altered--if it
 * contained an SSL struct prior to this call, that struct will remain.
 * @param conn The connection to assign a new client SSL struct to.
 * @returns 0 on success; -errno otherwise.
 */
int client_SSL_new(connection* conn, daemon_context* daemon) {

	SSL* new_ssl = SSL_new(daemon->client_ctx);
	if (new_ssl == NULL)
		return ssl_malloc_err(conn);

	if (conn->tls != NULL)
		SSL_free(conn->tls);
	conn->tls = new_ssl;

	return 0;
}

/**
 * Prepares a client connection by creating/configuring bufferevents and
 * setting hostname validation.
 *
 * @param sock_ctx The socket context of the connection to be set up.
 * @returns 0 on success; -errno on failure. In the event of a failure, it is
 * left to the calling function to clean up sock_ctx and set its error state.
 */
int client_connection_setup(sock_context* sock_ctx) {

	daemon_context* daemon = sock_ctx->daemon;
	connection* conn = sock_ctx->conn;
	char* hostname = sock_ctx->rem_hostname;
	int ret;

	if (hostname != NULL) {
		log_printf(LOG_INFO, "Hostname passed in is: %s\n", hostname);
		SSL_set_tlsext_host_name(conn->tls, hostname);
		ret = SSL_set1_host(conn->tls, hostname);
		if (ret != 1) {
			set_err_string(conn, "Connection setup error: "
					"couldn't assign hostname associated with the connection");
			ret = -ECONNABORTED; /* TODO: set SSL error here */
			goto err;
		}
	}

	/* socket set to -1 because we set it later */
	conn->plain.bev = bufferevent_socket_new(daemon->ev_base,
			NOT_CONN_BEV, BEV_OPT_CLOSE_ON_FREE);
	if (conn->plain.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Connection setup error: "
				"failed to allocate buffers within the SSA daemon");
		goto err;
	}

	conn->secure.bev = bufferevent_openssl_socket_new(daemon->ev_base,
			sock_ctx->fd, conn->tls, BUFFEREVENT_SSL_CONNECTING, 0);
	if (conn->secure.bev == NULL) {
		ret = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Connection setup error: "
				"failed to allocate buffers within the SSA daemon");
		goto err;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL */
	bufferevent_openssl_set_allow_dirty_shutdown(conn->secure.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(conn->secure.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);
	bufferevent_setcb(conn->plain.bev, common_bev_read_cb,
			common_bev_write_cb, client_bev_event_cb, sock_ctx);

	struct timeval read_timeout = {
			.tv_sec = EXT_CONN_TIMEOUT,
			.tv_usec = 0,
	};

	ret = bufferevent_set_timeouts(conn->secure.bev, &read_timeout, NULL);
	if (ret < 0) {
		ret = -ECONNABORTED;
		set_err_string(conn, "Connection setup error: "
				"failed to set timeouts within the daemon");
		goto err;
	}

	ret = bufferevent_enable(conn->secure.bev, EV_READ | EV_WRITE);
	if (ret < 0) {
		ret = -ECONNABORTED;
		set_err_string(conn, "Connection setup error: "
				"enabling read/write for connections within the daemon failed");
		goto err;
	}

	return 0;
 err:
	log_printf(LOG_ERROR, "Failed to set up client/server bev [direct mode]\n");
	/* NOTE: intentionally left to the calling function to clean up errors */
	return ret;
}


/*******************************************************************************
 *                            REVOCATION FUNCTIONS
 ******************************************************************************/

/**
 * Performs the desired revocation checks on a given connection
 * @param conn The connection to perform checks on.
 * @returns 0 if the checks were successfully started, -1 if no distribution 
 * points were found (and/or if the responder revocation methods are disabled),
 * or -2 if an unrecoverable error occurred.
 */
int begin_responder_revocation_checks(sock_context* sock_ctx) {

	X509* cert = SSL_get_peer_certificate(sock_ctx->conn->tls);
	char** ocsp_urls = NULL;
	int ocsp_url_cnt = 0;
	//char** crl_urls = NULL;
	char crl_url_cnt = 0;
	int ret;
		
	if (!(sock_ctx->revocation.state & NO_OCSP_RESPONDER_CHECKS)) {
		ocsp_urls = retrieve_ocsp_urls(cert, &ocsp_url_cnt);
		if (ocsp_urls == NULL)
			return -2;
	}

	if (!(sock_ctx->revocation.state & NO_CRL_RESPONDER_CHECKS)) {
		//parse crl urls
	}

	X509_free(cert);

	if (ocsp_url_cnt == 0 && crl_url_cnt == 0)
		return -1; // No responder distribution points to check
	

	if (ocsp_url_cnt > 0) {
		ret = launch_ocsp_checks(sock_ctx, ocsp_urls, ocsp_url_cnt);
		if (ret != 0) {
			free(ocsp_urls);
			return -2;
		}
	}

	if (crl_url_cnt > 0) {
		//begin_crl_responder_checks
		// increment conn->revocation.crl_responder_cnt
		// increment conn->revocation.num_responder_types
	}

	free(ocsp_urls);

	return 0;
}

/**
 * Retrieves the OCSP response stapled to the handshake in tls, and checks to 
 * see if the returned response is valid.
 * @param tls The TLS connection to retrieve the stapled response from (a 
 * handshake must be performed before calling this function).
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the stapled response was verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was verified and it contained 
 * the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status OR if no response was stapled.
 */
int check_stapled_response(SSL* tls) {

	unsigned char* stapled_resp;
	OCSP_BASICRESP* basicresp;
	int resp_len, ret;

	resp_len = SSL_get_tlsext_status_ocsp_resp(tls, &stapled_resp);
	if (resp_len < 0)
		return V_OCSP_CERTSTATUS_UNKNOWN;

	ret = get_ocsp_basicresp(stapled_resp, resp_len, &basicresp);
	if (ret != 0)
		return V_OCSP_CERTSTATUS_UNKNOWN;

	ret = check_ocsp_response(basicresp, tls);

	OCSP_BASICRESP_free(basicresp);
	
	return ret;
}

/**
 * Creates a new bufferevent and initiates an HTTP connection with the server 
 * specified by url. On success, the information about the given connection 
 * (such as the bufferevent and the url) is stored in the revocation context
 * of the given socket context.
 * @param sock_ctx The given socket context to initiate an OCSP client for.
 * @param url The URL of the OCSP responder for the client to connect to.
 * @returns 0 on success, or -1 if an error occurred.
 */
int launch_ocsp_client(sock_context* sock_ctx, char* url) {

	revocation_context* rev = &sock_ctx->revocation;
	rev_client* ocsp_client = &rev->ocsp_clients[rev->ocsp_client_cnt];
	struct bufferevent* bev = NULL;
	char* hostname = NULL;
	int port, ret;

	struct timeval read_timeout = {
		.tv_sec = OCSP_READ_TIMEOUT,
		.tv_usec = 0,
	};

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		goto err;

	ret = evutil_make_socket_nonblocking(fd);
	if (ret != 0)
		goto err;
	
	bev = bufferevent_socket_new(sock_ctx->daemon->ev_base, 
			fd, BEV_OPT_CLOSE_ON_FREE);
	if (bev == NULL)
		goto err;

	ret = bufferevent_set_timeouts(bev, &read_timeout, NULL);
	if (ret != 0)
		goto err;

	bufferevent_setcb(bev, ocsp_responder_read_cb, NULL, 
			ocsp_responder_event_cb, (void*) sock_ctx);

	// TODO: add support for IPv6 OCSP responders in future
	ret = parse_url(url, &hostname, &port, NULL);
	if (ret != 0)
		goto err;

	// TODO: at some point we'll use an evdns_base to make the DNS async
	ret = bufferevent_socket_connect_hostname(bev, 
			NULL, AF_INET, hostname, (int) port);
	if (ret != 0)
		goto err;

	ocsp_client->buffer = (unsigned char*) calloc(1, MAX_HEADER_SIZE + 1);
	if (ocsp_client->buffer == NULL) 
		goto err;

	ocsp_client->buf_size = MAX_HEADER_SIZE;
	ocsp_client->bev = bev;
	ocsp_client->url = url;
		
	rev->num_rev_checks++;
	rev->ocsp_client_cnt++;

	free(hostname);
	return 0;
 err:
	if (hostname != NULL)
		free(hostname);

	if (bev != NULL)
		bufferevent_free(bev);
	else if (fd != -1)
		close(fd);
	
	return -1;
}

/**
 * Initiates clients to connect to the given OCSP responder URLs and retrieve
 * OCSP revocation responses from them.
 * @param sock_ctx The socket context that the checks are being performed
 * on behalf of.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 */
int launch_ocsp_checks(sock_context* sock_ctx, char** urls, int num_urls) {

	revocation_context* rev = &sock_ctx->revocation;

	rev->ocsp_clients = calloc(MAX_OCSP_RESPONDERS, sizeof(rev_client));
	if (rev->ocsp_clients == NULL)
		return 0;


	for (int i = 0; i < num_urls && i < MAX_OCSP_RESPONDERS; i++)
		launch_ocsp_client(sock_ctx, urls[i]);

	if (rev->ocsp_client_cnt == 0)
		return -1;

	return 0;
}

/**
 * Initiates clients to connect to the given CRL responder URLs and retreive
 * Certificate Revocation Lists (CRLs) from them.
 * @param sock_ctx The socket context that the checks are being performed
 * on behalf of.
 * @param urls The URLs of OCSP responders for the clients to connect to.
 * @param num_ocsp_urls The number of URLs found in urls.
 */
int launch_crl_checks(sock_context* sock_ctx, char** urls, int num_urls) {

	for (int i = 0; i < num_urls; i++) {
		//char* url = crl_urls[i];

		//set up bufferevent here (with timeout),
		//pass in callbacks (with revocation_context* as the (void*) arg)
		//start the bufferevent's connection
	}

	return 0; // TODO: stub
}

/**
 * Parses the AUTHORITY_INFORMATION_ACCESS field out of a given X.509 
 * certificate and returns a list of URLS designating the location of the 
 * OCSP responders.
 * @param cert The X.509 certificate to parse OCSP responder information from.
 * @param num_urls The number of OCSP responder URLs parsed from cert.
 * @returns An allocated array of NULL-terminated strings containing the 
 * URLs of OCSP responders.
 */
char** retrieve_ocsp_urls(X509* cert, int* num_urls) {

	STACK_OF(OPENSSL_STRING) *url_sk = NULL;
	char** urls = NULL;
	url_sk = X509_get1_ocsp(cert);
	if (url_sk == NULL)
		return NULL;

	*num_urls = sk_OPENSSL_STRING_num(url_sk);
	if (*num_urls == 0)
		return NULL;

	urls = calloc(*num_urls, sizeof(char*));
	if (urls == NULL)
		return NULL;

	for (int i = 0; i < *num_urls; i++) 
		urls[i] = sk_OPENSSL_STRING_value(url_sk, i);

	sk_OPENSSL_STRING_free(url_sk);

	return urls;
}

/**
 * Parses the CRL_DISTRIBUTION_POINTS field out of a given X.509 certificate
 * and returns a list of URLs designating the location of the distribution 
 * points.
 * @param cert The X.509 certificate to parse distribution points out of.
 * @param num_urls The number of URLs returned.
 * @returns An allocated array of NULL-terminated strings containing the CRL
 * responder URLs.
 */
char** retrieve_crl_urls(X509* cert, int* num_urls) {

	return NULL; //TODO: stub
}

/**
 * Converts a given array of bytes into an OCSP_RESPONSE, checks its validity,
 * and extracts the basic response found within the response.
 * @param bytes The given bytes to convert.
 * @param len The length of bytes.
 * @param resp The OCSP basic response structure extracted from bytes.
 * @returns 0 on success, or -1 if an error occurred.
 */
int get_ocsp_basicresp(unsigned char* bytes, int len, OCSP_BASICRESP** resp) {

	OCSP_RESPONSE* full_response = NULL;
	const unsigned char* const_bytes = bytes;
	int ret;

	full_response = d2i_OCSP_RESPONSE(NULL, &const_bytes, (long)len);
	if (full_response == NULL)
		goto err;

	ret = OCSP_response_status(full_response);
	if (ret != OCSP_RESPONSE_STATUS_SUCCESSFUL)
		goto err;

	*resp = OCSP_response_get1_basic(full_response);
	if (*resp == NULL)
		goto err;

	OCSP_RESPONSE_free(full_response);
	return 0;
 err:
	if (full_response != NULL)
		OCSP_RESPONSE_free(full_response);

	return -1;
}


/**
 * Verifies the correctness of the signature and timestamps present in 
 * response and checks to make sure it matches the certificate found 
 * in tls. The OCSP response status found in response is then returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param tls The TLS connection to verify the response on.
 * @returns V_OCSP_CERTSTATUS_GOOD (0) if the response was properly verified 
 * and it contained a GOOD status for the certificate;
 * V_OCSP_CERTSTATUS_REVOKED (1) if the response was properly verified and it
 * contained the REVOKED status for the certificate; and
 * V_OCSP_CERTSTATUS_UNKNOWN (2) if the response could not be verified OR if 
 * the responder could not return a definitive answer on the certificate's
 * revocation status.
 */
int check_ocsp_response(OCSP_BASICRESP* resp, SSL* tls) {
	ASN1_GENERALIZEDTIME* revtime = NULL;
	ASN1_GENERALIZEDTIME* thisupd = NULL;
	ASN1_GENERALIZEDTIME* nextupd = NULL;
	STACK_OF(X509)* certs = NULL;
	X509_STORE* store = NULL;
	OCSP_CERTID* id = NULL;
	int ret, status, reason;

	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(tls));
	if (store == NULL)
		return V_OCSP_CERTSTATUS_UNKNOWN;

	certs = SSL_get_peer_cert_chain(tls);
    if (certs == NULL)
        return V_OCSP_CERTSTATUS_UNKNOWN;

    ret = OCSP_basic_verify(resp, certs, store, 0);
    if (ret != 1)
        return V_OCSP_CERTSTATUS_UNKNOWN;

    id = get_ocsp_certid(tls);
	if (id == NULL)
		return V_OCSP_CERTSTATUS_UNKNOWN;

    ret = OCSP_resp_find_status(resp, id, &status, &reason, 
            &revtime, &thisupd, &nextupd);
    if (ret != 1) {
		OCSP_CERTID_free(id);
        return V_OCSP_CERTSTATUS_UNKNOWN;
	}

	OCSP_CERTID_free(id);
    
    if (status != V_OCSP_CERTSTATUS_GOOD)
        return status;

    ret = OCSP_check_validity(thisupd, nextupd, LEEWAY_90_SECS, MAX_OCSP_AGE);
    if (ret != 1) {
        /* response too old */
        log_printf(LOG_ERROR, "cert is too old or invalid\n");
        status = V_OCSP_CERTSTATUS_UNKNOWN;
    }

	return V_OCSP_CERTSTATUS_GOOD;
}

/**
 * Verifies the correctness of the signature and timestamps present in the 
 * given CRL list and checks to see if it contains an entry for the certificate 
 * found in tls. If so, the CRL revoked status is returned.
 * If the response failes to validate, then the UNKNOWN status is returned.
 * @param response The response to verify the correctness of.
 * @param tls The TLS connection to verify the response on.
 * @returns 1 if a revoked status was found for the certificate in the CRL, or
 * 0 if no such status was found; or -1 if the response's correctness could not 
 * be verified.
 */
int check_crl_response(X509_CRL* response, SSL* tls) {

	return -1; //TODO: stub
}


/**
 * Forms an OCSP certificate ID from the peer's certificate chain found in tls.
 * @param tls The already-connected SSL object to form an OCSP_CERTID from.
 * @returns A newly-allocated OCSP_CERTID, or NULL on failure.
 */
OCSP_CERTID* get_ocsp_certid(SSL* tls) {

	STACK_OF(X509)* certs;
	X509* subject;
	X509* issuer;

	certs = SSL_get_peer_cert_chain(tls);
	if (certs == NULL || sk_X509_num(certs) < 2)
		return NULL;

	subject = sk_X509_value(certs, 0);
	issuer = sk_X509_value(certs, 1);

	return OCSP_cert_to_id(NULL, subject, issuer);
}

/**
 * Takes in a given URL and parses it into its hostname, port and path.
 * If no port is specified and the protocol is `http`, then the port specified 
 * will default to 80. Each output may be set to NULL safely (if only some
 * of the outputs are desired).
 * @param url The given url to parse.
 * @param host_out An address to populate with the hostname of the url.
 * @param port_out An address to populate with the numeric port of the url.
 * @param path_out An address to populate with the path of the url.
 * @returns 0 if the url could be successfully parsed, or -1 otherwise.
 */
int parse_url(char* url, char** host_out, int* port_out, char** path_out) {

	char* host;
	char* port_ptr;
	char* path;
	int ret, use_ssl;
	long port;

	ret = OCSP_parse_url(url, &host, &port_ptr, &path, &use_ssl);
	if (ret != 1)
		return -1;

	port = strtol(port_ptr, NULL, 10);
	if (port >= INT_MAX || port < 0)
		return -1;

	if (host_out != NULL)
		*host_out = host;
	else
		free(host);
	

	if (port_out != NULL)
		*port_out = port;

	free(port_ptr);


	if (path_out != NULL)
		*path_out = path;
	else
		free(path);

	return 0;
}

