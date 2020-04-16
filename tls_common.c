#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/err.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "netlink.h"
#include "tls_common.h"
#include "log.h"

#define MAX_BUFFER	1024*1024*10

int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist);
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers);
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len);


int get_port(struct sockaddr* addr) {
	int port = 0;
	if (addr->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)addr)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
	return port;
}

int sock_context_new(sock_context** ctx) {
	int ret = 0;
	*ctx = (sock_context*)calloc(1, sizeof(sock_context));
	if (*ctx == NULL)
		ret = -errno;
		/* could log_printf here; but remember {}s */
	return ret;
}

int connection_new(connection** conn, daemon_context* daemon) {
	int ret = 0;
	*conn = (connection*)calloc(1, sizeof(connection));
	if (*conn == NULL) {
		ret = -errno;
		log_printf(LOG_ERROR, "Failed to allocate connection: %s\n", strerror(errno));
	}
	(*conn)->daemon = daemon;
	return ret;
}

void connection_free(connection* conn) {
	if (conn == NULL) {
		log_printf(LOG_WARNING, "Tried to free a NULL connection.\n");
		return;
	}
	/* This breaks it for some reason...
	 * if (conn->tls != NULL)
	 *     SSL_free(conn->tls);
	*/
	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);
	free(conn);
	return;
}

int associate_fd(connection* conn, evutil_socket_t ifd) {
	int ret = 0;
	ret = bufferevent_setfd(conn->plain.bev, ifd);
	if (ret != 0)
		goto end;
	ret = bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);
	if (ret != 0)
		goto end;

	log_printf(LOG_INFO, "plain bev enabled\n");
 end:
	if (ret != 0)
		log_printf(LOG_ERROR, "associate_fd failed.\n");
	return ret;
}

void set_netlink_cb_params(connection* conn, daemon_context* daemon, 
		unsigned long id) {
	conn->daemon = daemon;
	conn->id = id;
}

/*
 *-----------------------------------------------------------------------------
 *                            CALLBACK FUNCTIONS
 *----------------------------------------------------------------------------- 
 */

void tls_bev_write_cb(struct bufferevent *bev, void *arg) {
	
	log_printf(LOG_DEBUG, "write event on bev %p\n", bev);

	connection* ctx = (connection*)arg;
	channel* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	struct evbuffer* out_buf;

	if (endpoint->closed == 1) {
		out_buf = bufferevent_get_output(bev);
		if (evbuffer_get_length(out_buf) == 0) {
			//bufferevent_free(bev);
			//shutdown_tls_conn_ctx(ctx);
		}
		return;
	}

	if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint->bev, EV_READ);
	}
	return;
}

void tls_bev_read_cb(struct bufferevent *bev, void *arg) {
	
	log_printf(LOG_DEBUG, "read event on bev %p\n", bev);
	
	connection* ctx = (connection*)arg;
	channel* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);

	/* clear read buffer if already closed */
	if (endpoint->closed == 1) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	if (in_len == 0)
		return;

	/* copy content from external buffer to internal buffer */
	out_buf = bufferevent_get_output(endpoint->bev);
	evbuffer_add_buffer(out_buf, in_buf);

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint->bev, EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg) {
	
	log_printf(LOG_DEBUG, "Made it into bev_event_cb\n");
	/* TODO: maybe split server and client functionality to make more readable? */
	connection* conn = (connection*)arg;
	unsigned long ssl_err;
	channel* endpoint = (bev == conn->secure.bev) ? &conn->plain : &conn->secure;
	channel* startpoint = (bev == conn->secure.bev) ? &conn->secure : &conn->plain;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_DEBUG, "%s endpoint connected\n", bev == conn->secure.bev ? "encrypted" : "plaintext");
		
		if (bev == conn->secure.bev) {
			log_printf(LOG_INFO, "Negotiated connection with %s\n", SSL_get_version(conn->tls));
			
			/* -1 means that we're the client */
			if (bufferevent_getfd(conn->plain.bev) == -1) {
				netlink_handshake_notify_kernel(conn->daemon, conn->id, 0);
			} else {
				bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);
				bufferevent_socket_connect(conn->plain.bev, conn->addr, conn->addrlen);
			}
		}
	}
	if (events & BEV_EVENT_ERROR) {
		log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", bev == conn->secure.bev ? "encrypted" : "plaintext");
		if (errno) {
			if (errno == ECONNRESET || errno == EPIPE) {
				log_printf(LOG_INFO, "Connection closed\n");
			}
			else {
				log_printf(LOG_INFO, "An unhandled error has occurred\n");
			}
			startpoint->closed = 1;
		}
		if (bev == conn->secure.bev) {
			while ((ssl_err = bufferevent_get_openssl_error(bev))) {
				log_printf(LOG_ERROR, "SSL error from bufferevent: %s [%s]\n",
					ERR_func_error_string(ssl_err),
					 ERR_reason_error_string(ssl_err));
			}
		}
		if (endpoint->closed == 0) {
			struct evbuffer* out_buf;
			out_buf = bufferevent_get_output(endpoint->bev);
			/* close other buffer if we're closing and it has no data left */
			if (evbuffer_get_length(out_buf) == 0) {
				endpoint->closed = 1;
			}
			startpoint->closed = 1;
		}
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_DEBUG, "%s endpoint got EOF\n", bev == conn->secure.bev ? "encrypted" : "plaintext");
		if (bufferevent_getfd(endpoint->bev) == -1) {
			endpoint->closed = 1;
		}
		else if (endpoint->closed == 0) {
			if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
				tls_bev_read_cb(endpoint->bev, conn);
			}
			if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0) {
				endpoint->closed = 1;
			}
		}
		startpoint->closed = 1;
	}
	/* If both channels are closed now, free everything */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		if (bufferevent_getfd(conn->plain.bev) == -1) {
			/* The -1 fd indicates that the daemon was attempting to connect when
			 * an error caused it to abort (such as a validation failure) */
			netlink_handshake_notify_kernel(conn->daemon, conn->id, -ECONNABORTED);
		}
		/* TODO: this function never actually did anything. Change this??? */
		/* shutdown_tls_conn_ctx(ctx); */
	}
	return;
}

/*
 *-----------------------------------------------------------------------------
 *                           GETSOCKOPT FUNCTIONS 
 *----------------------------------------------------------------------------- 
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
	int ret = 0;

	assert(conn);
	assert(conn->tls);

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
	
	assert(conn);
	assert(conn->tls);

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
 *-----------------------------------------------------------------------------
 *                           SETSOCKOPT FUNCTIONS
 *----------------------------------------------------------------------------- 
 */

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

	assert(conn);
	assert(conn->tls);
	assert(cipher);

	STACK_OF(SSL_CIPHER)* cipherlist = SSL_get_ciphers(conn->tls);
	if (cipherlist == NULL)
		return -EINVAL;

	int ret = clear_from_cipherlist(cipher, cipherlist);
	if (ret != 0)
		return -EINVAL;
	
	return 0;
}

/*
 *-----------------------------------------------------------------------------
 *                             HELPER FUNCTIONS
 *----------------------------------------------------------------------------- 
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
