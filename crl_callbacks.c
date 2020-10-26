#include <string.h>

#include <event2/bufferevent.h>
#include <event2/event.h>

#include "revocation.h"
#include "error.h"
//#include "daemon_structs.h"

crl_responder* get_last_crl_responder(crl_responder* list);
crl_responder* launch_crl_client(revocation_ctx* rev_ctx, char* url);
void crl_responder_event_cb(struct bufferevent* bev, short events, void* arg);
void crl_responder_read_cb(struct bufferevent* bev, void* arg);

//new_launch
int launch_crl_checks(revocation_ctx* rev_ctx, int cert_index) { //OCSP had cert_id; need something else?

	X509* cert = sk_X509_value(rev_ctx->certs, cert_index);

	crl_responder* last = NULL;
	crl_responder* new_responder;

	char** urls;
	int num_urls;
	int num_responders_queried = 0;

	urls = retrieve_crl_urls(cert, &num_urls);

	if (urls == NULL)
		return 0;

log_printf(LOG_DEBUG, "retrieved urls\n");

	if (has_cached_checks(rev_ctx->checks)) {
	log_printf(LOG_DEBUG, "has cached checks\n");
		for (int i = 0; i < num_urls && i < MAX_CRL_RESPONDERS; i++) {
		log_printf(LOG_DEBUG, "%d: %s, %d\n", i, urls[i], strlen(urls[i]));
			if (crl_in_cache(rev_ctx->daemon->crl_cache, urls[i])) {
				log_printf(LOG_DEBUG, "crl was in the cache\n");
				//if the crl is in the cache, but the serial number is not,
				//we return -1, and begin_revocation_checks interprets that
				//to mean that we don't need any responders to check this cert
	
				cdp_free(urls, num_urls);
				num_responders_queried = -1;
	
				return num_responders_queried;
			}
		}
	}

	last = get_last_crl_responder(rev_ctx->crl_responders); 

	for (int i = 0; i < num_urls && i < MAX_CRL_RESPONDERS; i++) {

		new_responder = launch_crl_client(rev_ctx, urls[i]);

		if (new_responder == NULL)
			continue;

		new_responder->cert_position = cert_index;

		num_responders_queried += 1;
		if (last == NULL)
			rev_ctx->crl_responders = new_responder;
		else 
			last->next = new_responder;
		last = new_responder;
    	}

	if (urls != NULL)
		free(urls);

	return num_responders_queried;
}



crl_responder* get_last_crl_responder(crl_responder* list) {

    if (list == NULL)
        return NULL;

    while (list->next != NULL)
        list = list->next;

    return list;
}

crl_responder* launch_crl_client(revocation_ctx* rev_ctx, char* url) {

    struct timeval read_timeout = { .tv_sec = OCSP_READ_TIMEOUT }; //TODO: what should crl timeout be?
	crl_responder* crl_resp;
    struct bufferevent* bev = NULL;
	char* hostname = NULL;
	int port;
	int ret;


    crl_resp = calloc(1, sizeof(crl_responder));
    if (crl_resp == NULL) {
        free(url);
        return NULL;
    }

	crl_resp->url = url;

    ret = parse_url(url, &hostname, &port, NULL);
	if (ret != 0)
		goto err;

    bev = bufferevent_socket_new(rev_ctx->daemon->ev_base, 
                -1, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL)
        goto err;

    crl_resp->bev = bev;

    ret = bufferevent_set_timeouts(bev, &read_timeout, NULL);
    if (ret != 0)
        goto err;

    bufferevent_setcb(bev, crl_responder_read_cb, NULL, 
            crl_responder_event_cb, (void*) crl_resp);

    ret = bufferevent_socket_connect_hostname(bev, 
            rev_ctx->daemon->dns_base, AF_UNSPEC, hostname, port);
    if (ret != 0)
        goto err;

    crl_resp->buffer = (unsigned char*) calloc(1, MAX_HEADER_SIZE + 1); //TODO: is MAX_HEADER_SIZE enough?
	if (crl_resp->buffer == NULL) 
		goto err;

	crl_resp->rev_ctx = rev_ctx;
	crl_resp->buf_size = MAX_HEADER_SIZE;

	crl_resp->hostname = SSL_get_servername(rev_ctx->sock_ctx->ssl, TLSEXT_NAMETYPE_host_name);

	free(hostname);
	return crl_resp;
err:
    if (crl_resp != NULL)
        crl_responder_free(crl_resp);
    if (hostname != NULL)
	free(hostname);

    return NULL;
}


void crl_responder_event_cb(struct bufferevent* bev, short events, void* arg) {

    log_printf(LOG_DEBUG, "event_cb\n");
    crl_responder* crl_resp = (crl_responder*) arg;
    revocation_ctx* rev_ctx = crl_resp->rev_ctx;
	int ret;

	if (events & BEV_EVENT_CONNECTED) {

		ret = send_crl_request(bev, crl_resp->url, NULL);
		if (ret != 0)
			goto err;


		ret = bufferevent_enable(bev, EV_READ | EV_WRITE);
		if (ret != 0)
			goto err;


	}
	if (events & BEV_EVENT_TIMEOUT || events & BEV_EVENT_ERROR) {
		LOG_E("Bufferevent timed out/encountered error\n");
		goto err;
	}

	return;
err:
    crl_responder_shutdown(crl_resp);

	rev_ctx->responders_at[crl_resp->cert_position]--;
	if (rev_ctx->responders_at[crl_resp->cert_position] == 0) {
		set_err_string(rev_ctx->sock_ctx, "TLS handshake failure: "
				"the certificate's revocation status could not be determined");
        
		fail_revocation_checks(rev_ctx);
	}
}


void crl_responder_read_cb(struct bufferevent* bev, void* arg) {
log_printf(LOG_DEBUG, "read cb\n");
    crl_responder* crl_resp = (crl_responder*) arg;
	revocation_ctx* rev_ctx = crl_resp->rev_ctx;
	X509_CRL *crl;

	int ret, status;
	int num_read;

	num_read = bufferevent_read(bev, &crl_resp->buffer[crl_resp->tot_read],
			crl_resp->buf_size - crl_resp->tot_read);

	crl_resp->tot_read += num_read;

	if (!crl_resp->is_reading_body) {

		if (strstr((char*)crl_resp->buffer, "\r\n\r\n") != NULL) {
			ret = start_reading_body((void*) crl_resp);
			if (ret != 0)
				goto err;

		} else if (crl_resp->tot_read == crl_resp->buf_size) {
			goto err;
		}
	}

	/* A connection could be all done reading both header and body in one go */
	if (done_reading_body((void*) crl_resp)) {

log_printf(LOG_DEBUG, "done reading body\n");

		hcmap_t* crl_cache;
		char* url;
		char* hostname;
		sem_t* cache_sem; //for crl update if crl is valid

		const unsigned char* raw_crl = crl_resp->buffer;

		crl = d2i_X509_CRL(NULL, &raw_crl, crl_resp->tot_read);

		X509* subject = sk_X509_value(rev_ctx->certs, crl_resp->cert_position);
		if (subject == NULL)
			goto err;

		X509* issuer = sk_X509_value(rev_ctx->certs, crl_resp->cert_position + 1);
		if (issuer == NULL)
			goto err;

		check_crl_response(crl, subject, issuer, &status);

//this if block prepares resources for being used after the crl_resp struct has been freed
		if (status == X509_V_OK || status == X509_V_ERR_CERT_REVOKED) { 
			crl_cache = rev_ctx->daemon->crl_cache;
			url = alloc_dup(crl_resp->url, (strlen(crl_resp->url) + 1));
			hostname = calloc(1, (strlen(crl_resp->hostname) + 1));
			strcpy(hostname, crl_resp->hostname);
			cache_sem = rev_ctx->daemon->cache_sem;
		}


		switch (status) {
		case X509_V_OK:

			log_printf(LOG_DEBUG, "about to pass\n");
			pass_individual_crl_check(crl_resp);
			log_printf(LOG_DEBUG, "about to update\n");
			crl_cache_update(crl_cache, crl, url, hostname, cache_sem);
			
			break;

		case X509_V_ERR_CERT_REVOKED:
			log_printf(LOG_DEBUG, "certificate was revoked\n");
			set_err_string(rev_ctx->sock_ctx, "TLS handshake error: "
					"certificate revoked (CRL)");
			fail_revocation_checks(rev_ctx);
			crl_cache_update(crl_cache, crl, url, hostname, cache_sem);
			break;
		default:
			goto err;
		}


 //TODO: look at other cases... what else could cause it to fail
	}

	X509_CRL_free(crl);
	return;
err:
	crl_responder_shutdown(crl_resp);
	if (crl != NULL)
		X509_CRL_free(crl);

	rev_ctx->crl_responders_at[crl_resp->cert_position]--;
	if (rev_ctx->crl_responders_at[crl_resp->cert_position] == 0) {

		set_err_string(rev_ctx->sock_ctx, "TLS handshake failure: "
				"the certficate's revocation status could not be determined");

		fail_revocation_checks(rev_ctx);
	}
}
