
#include <sys/un.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>

#include "config.h"
#include "daemon_structs.h"
#include "error.h"
#include "log.h"
#include "netlink.h"
#include "socket_setup.h"

#define HASHMAP_NUM_BUCKETS	100
#define CACHE_NUM_BUCKETS 20

/**
 * Creates a new daemon_ctx to be used throughout the life cycle
 * of a given SSA daemon. This context holds the netlink connection,
 * hashmaps to store socket_ctx information associated with active
 * connections, and client/server SSL_CTX objects that can be used
 * to initialize SSL connections to secure settings.
 * @param config_path A NULL-terminated string representing a path to
 * a .yml file that contains client/server settings. If this input is
 * NULL, the daemon will default secure settings.
 * @param port The port associated with this particular daemon. It is the
 * port that the daemon will listen on for new incoming connections from
 * an internal program.
 * @returns A pointer to an initialized daemon_ctx containing all 
 * relevant settings from config_path.
 */
daemon_ctx* daemon_context_new(char* config_path, int port) {

	daemon_ctx* daemon = NULL;
	
	daemon = calloc(1, sizeof(daemon_ctx));
	if (daemon == NULL)
		goto err;

	daemon->port = port;
	
	daemon->ev_base = event_base_new();
	if (daemon->ev_base == NULL)
		goto err;
	if (event_base_priority_init(daemon->ev_base, 3) != 0)
		goto err;

	daemon->dns_base = evdns_base_new(daemon->ev_base, 1);
	if (daemon->dns_base == NULL)
		goto err;

	daemon->sock_map = hashmap_create(HASHMAP_NUM_BUCKETS);
	if (daemon->sock_map == NULL)
		goto err;

	daemon->sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS);
	if (daemon->sock_map_port == NULL)
		goto err;

	daemon->revocation_cache = str_hashmap_create(HASHMAP_NUM_BUCKETS);
	if (daemon->revocation_cache == NULL)
		goto err;

    /*
	daemon->ssl_ctx_cache = str_hashmap_create(HASHMAP_NUM_BUCKETS);
	if (daemon->revocation_cache == NULL)
		goto err;
     */

	daemon->settings = parse_config(config_path);
	if (daemon->settings == NULL)
		goto err;

	/* Setup netlink socket */
	/* Set up non-blocking netlink socket with event base */
	daemon->netlink_sock = netlink_connect(daemon);
	if (daemon->netlink_sock == NULL)
		goto err;
	
	
	int nl_fd = nl_socket_get_fd(daemon->netlink_sock);
	if (evutil_make_socket_nonblocking(nl_fd) != 0)
		goto err;

	return daemon;
err:
	if (daemon != NULL)
		daemon_context_free(daemon);

	if (errno)
		log_printf(LOG_ERROR, "Error creating daemon: %s\n", strerror(errno));
	return NULL;
}


/**
 * Frees a given daemon context and all of its internals, including 
 * sock_contexts of active connections.
 * @param daemon A pointer to the daemon_context to free.
 */
void daemon_context_free(daemon_ctx* daemon) {

    if (daemon == NULL)
        return;

    if (daemon->dns_base != NULL)
        evdns_base_free(daemon->dns_base, 1);

    if (daemon->revocation_cache != NULL)
        str_hashmap_deep_free(daemon->revocation_cache,
                    (void (*)(void*)) OCSP_BASICRESP_free);
    
    /*
    if (daemon->ssl_ctx_cache != NULL)
        str_hashmap_deep_free(daemon->ssl_ctx_cache,
                    (void (*)(void*)) SSL_CTX_free);
     */

    if (daemon->settings != NULL)
        global_settings_free(daemon->settings);

    if (daemon->netlink_sock != NULL)
        netlink_disconnect(daemon->netlink_sock);

    if (daemon->sock_map_port != NULL)
        hashmap_free(daemon->sock_map_port);

    if (daemon->sock_map != NULL)
        hashmap_deep_free(daemon->sock_map, 
                    (void (*)(void*))socket_context_free);

    if (daemon->ev_base != NULL)
        event_base_free(daemon->ev_base);

    free(daemon);
}



/**
 * Allocates a new socket_ctx and assigns it the given id.
 * @param sock_ctx A memory address to be populated with the socket_ctx
 * pointer.
 * @param daemon The daemon_ctx of the running daemon.
 * @param id The ID assigned to the given socket_ctx.
 * @returns 0 on success, or -ECANCELED if an error occurred.
 */
int socket_context_new(socket_ctx** new_sock_ctx, int fd,  
		daemon_ctx* daemon, unsigned long id) {

    socket_ctx* sock_ctx = (socket_ctx*)calloc(1, sizeof(socket_ctx));
    if (sock_ctx == NULL)
        goto err;

    sock_ctx->ssl_ctx = SSL_CTX_create(daemon->settings);
    if (sock_ctx->ssl_ctx == NULL)
        goto err;

    sock_ctx->daemon = daemon;
    sock_ctx->id = id;
    sock_ctx->sockfd = fd;
    sock_ctx->state = SOCKET_NEW;
    sock_ctx->rev_ctx.daemon = daemon;
    sock_ctx->rev_ctx.id = id;

    /* transfer over revocation check flags */
    sock_ctx->rev_ctx.checks = daemon->settings->revocation_checks;

    int ret = hashmap_add(daemon->sock_map, id, sock_ctx);
    if (ret != 0)
        goto err;

    *new_sock_ctx = sock_ctx;

    return 0;
err:
    log_global_error(LOG_ERROR, "Socket context failed to be created");

    if (sock_ctx != NULL)
        socket_context_free(sock_ctx);

    *new_sock_ctx = NULL;
    return -ECANCELED; 
}

socket_ctx* accepting_socket_ctx_new(socket_ctx* listener_ctx, int fd) {
    
    daemon_ctx* daemon = listener_ctx->daemon;
    socket_ctx* sock_ctx = NULL;
    int ret;

    sock_ctx = (socket_ctx*)calloc(1, sizeof(socket_ctx));
	if (sock_ctx == NULL)
        return NULL;

    sock_ctx->daemon = daemon;
    sock_ctx->sockfd = fd; /* standard to show not connected */
    sock_ctx->state = SOCKET_CONNECTING;

    ret = SSL_CTX_up_ref(listener_ctx->ssl_ctx);
    if (ret != 1)
        goto err;

    sock_ctx->ssl_ctx = listener_ctx->ssl_ctx;

    return sock_ctx;
err:
    if (sock_ctx != NULL)
        free(sock_ctx);

    close(fd);

    return NULL;  
}

/**
 * Closes and frees all of the appropriate file descriptors/structs within a 
 * given socket_ctx. This function should be called before the connection
 * is set to a different state, as it checks the state to do particular
 * shutdown tasks. This function does not alter state.
 * @param sock_ctx The given socket_ctx to shut down.
 */
void socket_shutdown(socket_ctx* sock_ctx) {

    revocation_context_cleanup(&sock_ctx->rev_ctx);

    if (sock_ctx->ssl != NULL) {
        switch (sock_ctx->state) {
        case SOCKET_CONNECTED:
        case SOCKET_FINISHING_CONN:
        case SOCKET_ACCEPTED:
            SSL_shutdown(sock_ctx->ssl);
            break;
        default:
            break;
        }

        SSL_free(sock_ctx->ssl);
    }

    sock_ctx->ssl = NULL;

    if (sock_ctx->listener != NULL) 
        evconnlistener_free(sock_ctx->listener);
    sock_ctx->listener = NULL;

    if (sock_ctx->secure.bev != NULL)
        bufferevent_free(sock_ctx->secure.bev);
    sock_ctx->secure.bev = NULL;
	sock_ctx->secure.closed = 1;
	
	if (sock_ctx->plain.bev != NULL)
		bufferevent_free(sock_ctx->plain.bev);
	sock_ctx->plain.bev = NULL;
	sock_ctx->plain.closed = 1;

	if (sock_ctx->sockfd != -1)
		close(sock_ctx->sockfd);
	sock_ctx->sockfd = -1;

	return;
}

/**
 * Frees a given socket_ctx and all of its internal structures. 
 * This function is provided to the hashmap implementation so that it can 
 * correctly free all held data.
 * @param sock_ctx The socket_ctx to be free
 */
void socket_context_free(socket_ctx* sock_ctx) {

	if (sock_ctx == NULL) {
		log_printf(LOG_WARNING, "Tried to free a null sock_ctx reference\n");
		return;
	}

	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
	} else if (sock_ctx->sockfd != -1) { 
		EVUTIL_CLOSESOCKET(sock_ctx->sockfd);
	}

	revocation_context_cleanup(&sock_ctx->rev_ctx);
	
    if (sock_ctx->ssl_ctx != NULL)
        SSL_CTX_free(sock_ctx->ssl_ctx);

    if (sock_ctx->ssl != NULL)
	    SSL_free(sock_ctx->ssl);
	if (sock_ctx->secure.bev != NULL)
		bufferevent_free(sock_ctx->secure.bev);
	if (sock_ctx->plain.bev != NULL)
		bufferevent_free(sock_ctx->plain.bev);

    free(sock_ctx);
	return;
}


void socket_context_erase(socket_ctx* sock_ctx, int port) {

    daemon_ctx* daemon = sock_ctx->daemon;

    log_printf(LOG_DEBUG, "Erasing connection completely\n");
	
    hashmap_del(daemon->sock_map_port, port);

	socket_shutdown(sock_ctx);
	socket_context_free(sock_ctx);
}


/**
 * Prepares a given revocation context to perform revocation checks on a 
 * certificate chain. The corresponding function `revocation_context_cleanup`
 * can be used to free any memory and clear any entries set by this function.
 * @param rev_ctx The revocation context to prepare.
 * @param sock_ctx The socket context to be associated with the given revocation
 * context.
 * @returns 0 on success, or -1 if an error occured allocating memory/retrieving
 * TLS connection information from the socket.
 */
int revocation_context_setup(revocation_ctx* rev_ctx, socket_ctx* sock_ctx) {

    STACK_OF(X509)* certs;

    rev_ctx->sock_ctx = sock_ctx;
    rev_ctx->daemon = sock_ctx->daemon;
    rev_ctx->id = sock_ctx->id;

    certs = SSL_get_peer_cert_chain(sock_ctx->ssl);
    if (certs == NULL || sk_X509_num(certs) == 0)
        return -1;

    rev_ctx->certs = sk_X509_dup(certs);
    if (rev_ctx->certs == NULL)
        return -1;

    rev_ctx->store = SSL_CTX_get_cert_store(sock_ctx->ssl_ctx);
    if (rev_ctx->store == NULL)
        return -1;

    rev_ctx->total_to_check = sk_X509_num(rev_ctx->certs) - 1;
    rev_ctx->left_to_check = rev_ctx->total_to_check;

    rev_ctx->responders_at = calloc(rev_ctx->total_to_check, sizeof(int));
    if (rev_ctx->responders_at == NULL)
        return -1;

    rev_ctx->crl_responders_at = calloc(rev_ctx->total_to_check, sizeof(int));
    if (rev_ctx->crl_responders_at == NULL)
        return -1;

    

    return 0;
}

void revocation_context_cleanup(revocation_ctx* rev_ctx) {

    if (rev_ctx->responders_at != NULL)
        free(rev_ctx->responders_at);
    rev_ctx->responders_at = NULL;

    if (rev_ctx->crl_responders_at != NULL)
        free(rev_ctx->crl_responders_at);
    rev_ctx->crl_responders_at = NULL;

    ocsp_responder* curr = rev_ctx->ocsp_responders;
    while (curr != NULL) {
        ocsp_responder* next = curr->next;
        ocsp_responder_free(curr);
        curr = next;
    }
    rev_ctx->ocsp_responders = NULL;

    if (rev_ctx->certs != NULL)
        sk_X509_free(rev_ctx->certs);
    rev_ctx->certs = NULL;

    /* free CRL responders here too */
    return;
}

void ocsp_responder_shutdown(ocsp_responder* resp) {

    if (resp->bev != NULL)
        bufferevent_free(resp->bev);
    resp->bev = NULL;

    if (resp->buffer != NULL)
        free(resp->buffer);
    resp->buffer = NULL;

    if (resp->url != NULL)
        free(resp->url);
    resp->url = NULL;

    if (resp->certid != NULL)
        OCSP_CERTID_free(resp->certid);
    resp->certid = NULL;

    return;
}

void ocsp_responder_free(ocsp_responder* resp) {

    ocsp_responder_shutdown(resp);
    free(resp);
}


/**
 * Checks the given socket to see if it matches any of the corresponding
 * states passed into the function. If not, the error string of the connection 
 * is set and a negative error code is returned. Any state or combination of 
 * states may be checked using this function (even CONN_ERROR), provided the
 * number of states to check are accurately reported in num.
 * @param sock_ctx The context of the socket to verify.
 * @param num The number of connection states listed in the function arguments.
 * @param ... The variadic list of connection states to check.
 * @returns 0 if the state was one of the acceptable states listed, -EBADFD if 
 * the state was CONN_ERROR when it shouldn't be, or -EOPNOTSUPP otherwise.
 */
int check_socket_state(socket_ctx* sock_ctx, int num, ...) {

	va_list args;

	va_start(args, num);

	for (int i = 0; i < num; i++) {
		enum socket_state state = va_arg(args, enum socket_state);
		if (sock_ctx->state == state)
			return 0;
	}
	va_end(args);

	switch(sock_ctx->state) {
	case SOCKET_ERROR:
		set_badfd_err_string(sock_ctx);
		return -EBADFD;
	default:
		set_wrong_state_err_string(sock_ctx);
		return -EOPNOTSUPP;
	}
}


/**
 * Retrieves an integer port number from a given sockaddr struct.
 * @param addr The sockaddr struct to retrieve the port number of.
 * @returns The port number.
 */
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