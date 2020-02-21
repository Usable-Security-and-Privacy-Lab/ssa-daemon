#include "tls_common.h"
#include "log.h"

void associate_fd(connection* conn, evutil_socket_t ifd) {
	bufferevent_setfd(conn->plain.bev, ifd);
	bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);

	log_printf(LOG_INFO, "plain bev enabled\n");
	return;
}

int get_peer_certificate(connection* conn_ctx, char** data, unsigned int* len) {
	X509* cert;
	BIO* bio;
	char* bio_data;
	char* pem_data;
	unsigned int cert_len;

	if (conn_ctx->tls == NULL) {
		return 0;
	}
	cert = SSL_get_peer_certificate(conn_ctx->tls);
	if (cert == NULL) {
		return 0;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		X509_free(cert);
		return 0;
	}
	if (PEM_write_bio_X509(bio, cert) == 0) {
		X509_free(cert);
		BIO_free(bio);
		return 0;
	}

	cert_len = BIO_get_mem_data(bio, &bio_data);
	pem_data = malloc(cert_len + 1); /* +1 for null terminator */
	if (pem_data == NULL) {
		X509_free(cert);
		BIO_free(bio);
		return 0;
	}

	memcpy(pem_data, bio_data, cert_len);
	pem_data[cert_len] = '\0';
	X509_free(cert);
	BIO_free(bio);

	*data = pem_data;
	*len = cert_len;
	return 1;
}

int get_peer_identity(connection* conn_ctx, char** data, unsigned int* len) {
	X509* cert;
	X509_NAME* subject_name;
	char* identity;
	if (conn_ctx->tls == NULL) {
		return 0;
	}
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
