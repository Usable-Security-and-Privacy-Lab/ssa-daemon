#include <event2/bufferevent.h>
#include <errno.h>
#include <string.h>

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


void connection_free(connection* ctx) {
	/* TODO: This function never actually did anything. Change this?? */
	/* shutdown_tls_conn_ctx(ctx); */
	ctx->tls = NULL;
	if (ctx->secure.bev != NULL) {
		// && ctx->secure.closed == 0) {
		 bufferevent_free(ctx->secure.bev);
	}
	ctx->secure.bev = NULL;
	if (ctx->plain.bev != NULL) {
		// && ctx->plain.closed == 1) {
		 bufferevent_free(ctx->plain.bev);
	}
	ctx->plain.bev = NULL;
	free(ctx);
	return;
}

void associate_fd(connection* conn, evutil_socket_t ifd) {
	bufferevent_setfd(conn->plain.bev, ifd);
	bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);

	log_printf(LOG_INFO, "plain bev enabled\n");
	return;
}

int set_netlink_cb_params(connection* conn, daemon_context* daemon_ctx, unsigned long id) {
	/*if (conn->tls == NULL) {
		return 1;
	}*/
	conn->daemon = daemon_ctx;
	conn->id = id;
	return 1;
}

/*
 *-----------------------------------------------------------------------------
 *                            CALLBACK FUNCTIONS
 *----------------------------------------------------------------------------- 
 */

void tls_bev_write_cb(struct bufferevent *bev, void *arg) {
	//log_printf(LOG_DEBUG, "write event on bev %p\n", bev);
	connection* ctx = arg;
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
	//log_printf(LOG_DEBUG, "read event on bev %p\n", bev);
	connection* ctx = arg;
	channel* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	
	if (endpoint->closed == 1) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	if (in_len == 0) {
		return;
	}

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
	connection* ctx = arg;
	unsigned long ssl_err;
	channel* endpoint = (bev == ctx->secure.bev) ? &ctx->plain : &ctx->secure;
	channel* startpoint = (bev == ctx->secure.bev) ? &ctx->secure : &ctx->plain;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_DEBUG, "%s endpoint connected\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		//startpoint->connected = 1;
		if (bev == ctx->secure.bev) {
			//log_printf(LOG_INFO, "Is handshake finished?: %d\n", SSL_is_init_finished(ctx->tls));
			log_printf(LOG_INFO, "Negotiated connection with %s\n", SSL_get_version(ctx->tls));
			if (bufferevent_getfd(ctx->plain.bev) == -1) {
				netlink_handshake_notify_kernel(ctx->daemon, ctx->id, 0);
			}
			else {
				bufferevent_enable(ctx->plain.bev, EV_READ | EV_WRITE);
				bufferevent_socket_connect(ctx->plain.bev, ctx->addr, ctx->addrlen);
			}
		}
	}
	if (events & BEV_EVENT_ERROR) {
		//log_printf(LOG_DEBUG, "%s endpoint encountered an error\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		if (errno) {
			if (errno == ECONNRESET || errno == EPIPE) {
				log_printf(LOG_INFO, "Connection closed\n");
			}
			else {
				log_printf(LOG_INFO, "An unhandled error has occurred\n");
			}
			startpoint->closed = 1;
		}
		if (bev == ctx->secure.bev) {
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
		log_printf(LOG_DEBUG, "%s endpoint got EOF\n", bev == ctx->secure.bev ? "encrypted" : "plaintext");
		if (bufferevent_getfd(endpoint->bev) == -1) {
			endpoint->closed = 1;
		}
		else if (endpoint->closed == 0) {
			if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
				tls_bev_read_cb(endpoint->bev, ctx);
			}
			if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0) {
				endpoint->closed = 1;
			}
		}
		startpoint->closed = 1;
	}
	/* If both channels are closed now, free everything */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		if (bufferevent_getfd(ctx->plain.bev) == -1) {
			netlink_handshake_notify_kernel(ctx->daemon, ctx->id, -EHOSTUNREACH);
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

int get_peer_certificate(connection* conn, char** data, unsigned int* len) {
	X509* cert;
	BIO* bio;
	char* bio_data;
	char* pem_data;
	unsigned int cert_len;
	int did_succeed = 0;

	if (conn->tls == NULL)
		return 0;
	cert = SSL_get_peer_certificate(conn->tls);
	if (cert == NULL)
		return 0;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto end;
	if (PEM_write_bio_X509(bio, cert) == 0)
		goto end;

	cert_len = BIO_get_mem_data(bio, &bio_data);
	pem_data = malloc(cert_len + 1); /* +1 for null terminator */
	if (pem_data == NULL)
		goto end;

	memcpy(pem_data, bio_data, cert_len);
	pem_data[cert_len] = '\0';

	did_succeed = 1;
	*data = pem_data;
	*len = cert_len; /* BUG: shouldnt this be cert_len + 1?? */
 end:
	X509_free(cert);
	BIO_free(bio);
	return did_succeed;
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

char* get_enabled_ciphers(connection* conn, char** data) {
	assert(conn);
	assert(conn->tls);

	STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(conn->tls);
	/* TODO: replace this with SSL_get1_supported_ciphers? Maybe... */

	int ciphers_len = get_ciphers_strlen(ciphers);
	char* ciphers_str = (char*) malloc(ciphers_len);
	/* TODO: handle malloc failures... */
	if (!get_ciphers_string(ciphers, ciphers_str, ciphers_len)) {
		/* TODO: once again, shouldnt happen... */
		return 0;
	}
	*data = ciphers_str;
	return 1;
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

	if (conn_ctx == NULL)
		return 0;

	STACK_OF(X509_NAME)* cert_names = SSL_load_client_CA_file(value);
	if (cert_names == NULL)
		return 0;

	SSL_set_client_CA_list(conn_ctx->tls, cert_names);
	return 1;
}

int disable_cipher(connection* conn, char* cipher) {
	assert(conn);
	assert(conn->tls);
	assert(cipher);

	STACK_OF(SSL_CIPHER)* cipherlist = SSL_get_ciphers(conn->tls);
	int ciphers_len = clear_from_cipherlist(cipher, cipherlist);
	
	char* ciphers_string = (char*) malloc(ciphers_len);
	if (!get_ciphers_string(cipherlist, ciphers_string,ciphers_len)) {
		/* TODO: print error here. Realistically, this should never
		happen if we've written this function right... */
		return -1;
	}
	
	if (!SSL_set_cipher_list(conn->tls, ciphers_string)) {
		free(new_ciphers);
		/* TODO: figure out standard error code returns for functions */
		return -1;
	}

	free(new_ciphers);
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
 * @returns 1 on success; 0 if the buffer was not big enough to store all of
 * the ciphers and had to be truncated.
 */
int get_ciphers_string(STACK_OF(SSL_CIPHER)* ciphers, char* buf, int buf_len) {
	int index = 0;
	for (int i = 0; i < sk_SSL_CIPHER_num(cipherlist); i++) {
		SSL_CIPHER curr = sk_SSL_CIPHER_value(cipherlist, i);
		char* cipher = SSL_CIPHER_get_name(curr);
		
		if (index + strlen(cipher) >= buf_len) {
			buf[index-1] = '\0';
			return 0; /* buf not big enough */
		}
		
		strcpy(&buf[index], cipher);
		buf[index + strlen(cipher)] = ':';

		index += strlen(cipher) + 1;
	}
	buf[index - 1] = '\0';
	return 1;
}

/**
 * Determine the combined string length of all the cipher strings.
 * @param ciphers The cipher list to measure string lengths from.
 * @returns The combined string length of the ciphers in the list (as if 
 * there were ':' characters between each cipher and a null-terminating
 * '\0' at the end).
 */
int get_ciphers_strlen(STACK_OF(SSL_CIPHER)* ciphers) {
	int len = 0;
	for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		char* curr = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
		len += strlen(curr) + 1;
	}
	return len;
}

/**
 * Iterates through the stack of ciphers and clears out ones matching
 * the given cipher name. Returns the updated cumulative length of the ciphers.
 * @param cipher The string name of the cipher to be cleared from the list.
 * @param cipherlist The stack of ciphers to be modified.
 * @returns The combined string length of the remaining ciphers in the list
 * (as if there were ':' characters between each cipher and a null-terminating
 * '\0' at the end).
 */
int clear_from_cipherlist(char* cipher, STACK_OF(SSL_CIPHER)* cipherlist) {
	int length = 0, i = 0;

	while (i < sk_SSL_CIPHER_num(cipherlist)) {
		SSL_CIPHER curr_cipher = sk_SSL_CIPHER_value(cipherlist, i);
		char* cipher = SSL_CIPHER_get_name(curr_cipher);
		if (strcmp(name, cipher) == 0) {
			sk_SSL_CIPHER_delete(cipherlist, i);
		} else {
			length += strlen(cipher) + 1; /* +1 for ':' or '\0' */
			i++;
		}
	}
	/* assert: all ciphers to remove now removed */

	return length;
}
