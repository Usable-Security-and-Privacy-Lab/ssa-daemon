
#include <sys/un.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "daemon_structs.h"
#include "log.h"
#include "netlink.h"
#include "tls_client.h"
#include "tls_server.h"


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

	daemon->revocation_cache = hashmap_create(HASHMAP_NUM_BUCKETS);
	if (daemon->revocation_cache == NULL)
		goto err;

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
		hashmap_deep_str_free(daemon->revocation_cache, (void (*)(void*))OCSP_BASICRESP_free);

	if (daemon->settings != NULL)
        global_settings_free(daemon->settings);

	if (daemon->netlink_sock != NULL)
		netlink_disconnect(daemon->netlink_sock);

	if (daemon->sock_map_port != NULL)
		hashmap_free(daemon->sock_map_port);

	if (daemon->sock_map != NULL)
		hashmap_deep_free(daemon->sock_map, (void (*)(void*))socket_context_free);
	
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
 * @returns 0 on success, or -errno if an error occurred.
 */
int socket_context_new(socket_ctx** new_sock_ctx, int fd,  
		daemon_ctx* daemon, unsigned long id) {

    socket_ctx* sock_ctx = NULL;
    int response = 0;

	sock_ctx = (socket_ctx*)calloc(1, sizeof(socket_ctx));
	if (sock_ctx == NULL)
		return -errno;

    sock_ctx->ssl_ctx = SSL_CTX_create(daemon->settings);
    if (sock_ctx->ssl_ctx == NULL) {
        /* TODO: also should return -EINVAL if settings failed to load?? */
        response = -ENOMEM;
        goto err;
    }

    response = connection_new(&(sock_ctx->conn));
	if (response != 0)
		goto err;

	sock_ctx->daemon = daemon;
	sock_ctx->id = id;
	sock_ctx->fd = fd; /* standard to show not connected */
    sock_ctx->state = SOCKET_NEW;

    if (!daemon->settings->revocation_checks)
        sock_ctx->revocation.checks |= NO_REVOCATION_CHECKS;

    int ret = hashmap_add(daemon->sock_map, id, sock_ctx);
    if (ret != 0) {
        response = -errno;
        goto err;
    }

    *new_sock_ctx = sock_ctx;

	return 0;
 err:
    if (sock_ctx != NULL)
        socket_context_free(sock_ctx);

    *new_sock_ctx = NULL;

    return response; 
}

socket_ctx* accepting_socket_ctx_new(socket_ctx* listener_ctx, int fd) {
    
    daemon_ctx* daemon = listener_ctx->daemon;
    socket_ctx* sock_ctx = NULL;
    int response = 0;

    sock_ctx = (socket_ctx*)calloc(1, sizeof(socket_ctx));
	if (sock_ctx == NULL)
		return NULL;

    response = connection_new(&(sock_ctx->conn));
	if (response != 0)
		goto err;

	sock_ctx->daemon = daemon;
	sock_ctx->fd = fd; /* standard to show not connected */
    sock_ctx->state = SOCKET_CONNECTING;

    sock_ctx->conn->ssl = SSL_new(listener_ctx->ssl_ctx);
    if (sock_ctx->conn->ssl == NULL)
        goto err;

    return sock_ctx;
 err:
    if (sock_ctx != NULL)
        socket_context_free(sock_ctx);

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
	
	connection* conn = sock_ctx->conn;

	if (conn->ssl != NULL) {
		switch (sock_ctx->state) {
        case SOCKET_REV_CHECKING:
		case SOCKET_CONNECTED:
        case SOCKET_ACCEPTED:
			SSL_shutdown(conn->ssl);
			break;
		default:
			break;
		}
		SSL_free(conn->ssl);
	}
	
	conn->ssl = NULL;

	if (sock_ctx->listener != NULL) 
		evconnlistener_free(sock_ctx->listener);

	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	conn->secure.bev = NULL;
	conn->secure.closed = 1;
	
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);
	conn->plain.bev = NULL;
	conn->plain.closed = 1;

	if (sock_ctx->fd != -1)
		close(sock_ctx->fd);
	sock_ctx->fd = -1;

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
	} else if (sock_ctx->fd != -1) { 
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}

	revocation_context_cleanup(&sock_ctx->revocation);
	
	if (sock_ctx->conn != NULL)
		connection_free(sock_ctx->conn);

    if (sock_ctx->ssl_ctx != NULL)
        SSL_CTX_free(sock_ctx->ssl_ctx);

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


void revocation_context_cleanup(revocation_ctx* ctx) {

	if (ctx->crl_clients != NULL) {
		for (int i = 0; i < ctx->crl_client_cnt; i++) {
			responder_cleanup(&ctx->crl_clients[i]);
		}
		free(ctx->crl_clients);
		ctx->crl_clients = NULL;
	}

	if (ctx->ocsp_clients != NULL) {
		for (int i = 0; i < ctx->ocsp_client_cnt; i++) {
			responder_cleanup(&ctx->ocsp_clients[i]);
		}
		free(ctx->ocsp_clients);
		ctx->ocsp_clients = NULL;
	}
}

void responder_cleanup(responder_ctx* resp) {

	if (resp->bev != NULL) {
		bufferevent_free(resp->bev);
		resp->bev = NULL;
	}

	if (resp->buffer != NULL) {
		free(resp->buffer);
		resp->buffer = NULL;
	}

	if (resp->url != NULL) {
		free(resp->url);
		resp->url = NULL;
	}
}


/**
 * Creates a new connection struct and assigns it to conn.
 * @param conn The address to be assigned a new connection.
 * @returns 0 on success, or -errno if an error occurred.
 */
int connection_new(connection** conn) {

	(*conn) = (connection*)calloc(1, sizeof(connection));
	if (*conn == NULL)
		return -errno;

	(*conn)->err_string = calloc(1, MAX_ERR_STRING+1); /* +1 for '\0' */
	if ((*conn)->err_string == NULL)
		return -errno;
	
	return 0;
}


/**
 * Frees a given connection and all of its internal structures.
 * @param conn The connection to free.
 */ 
void connection_free(connection* conn) {

	if (conn == NULL) {
		log_printf(LOG_WARNING, "Tried to free a NULL connection.\n");
		return;
	}

	if (conn->ssl != NULL)
	    SSL_free(conn->ssl);
	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);

	free(conn->err_string);
	free(conn);
	return;
}

/**
 * Checks the given connection to see if it matches any of the corresponding
 * states passed into the function. If not, the error string of the connection 
 * is set and a negative error code is returned. Any state or combination of 
 * states may be checked using this function (even CONN_ERROR), provided the
 * number of states to check are accurately reported in num.
 * @param conn The connection to verify.
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
		set_badfd_err_string(sock_ctx->conn);
		return -EBADFD;
	default:
		set_wrong_state_err_string(sock_ctx->conn);
		return -EOPNOTSUPP;
	}
}


/**
 * Converts the current OpenSSL ERR error code into an appropriate errno code.
 * @returns 0 if no ERR was in the queue; -1 if the error could not be converted
 * into an error code; or a positive errno code.
 */
int ssl_err_to_errno() {

	unsigned long ssl_err = ERR_peek_error();

	/* TODO: stub */
	log_printf(LOG_ERROR, "OpenSSL error occurred:\n");

	switch (ERR_GET_REASON(ssl_err)) {
	case ERR_R_MALLOC_FAILURE:
		return ENOMEM;
	case ERR_R_PASSED_NULL_PARAMETER:
	case ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED:
	case ERR_R_PASSED_INVALID_ARGUMENT:
		return EINVAL;
	default:
		return ENETDOWN; /* some unrecoverable error internal to the Daemon */
	}
}

/**
 * Verifies that a given OpenSSL operation failed because of memory issues. If 
 * memory issues were not the cause of the problem, then the cause of the 
 * problem is most likely a bug internal to the daemon (such as passing in a 
 * NULL reference), and it will print out the error information to the logs.
 * @param conn The connection for which to associate the error string with.
 * @returns -ENOMEM when insufficient memory is available, or -ENOTRECOVERABLE 
 * when an unknown failure occurred.
 */
int ssl_malloc_err(connection* conn) {
	
	unsigned long ssl_err = ERR_get_error();
	ERR_clear_error();

	set_err_string(conn, "Daemon failed to allocate sufficient buffers: %s", 
			ERR_reason_error_string(ERR_GET_REASON(ssl_err)));

	if (ERR_GET_REASON(ssl_err) == ERR_R_MALLOC_FAILURE) {
		log_printf(LOG_ERROR, "OpenSSL malloc failure caught\n");
		set_err_string(conn, "Insufficient alloc memory for the SSA daemon");
		return -ENOMEM;
	} else { 
		log_printf(LOG_ERROR, "Internal OpenSSL error on malloc attempt: %s\n",
				ERR_error_string(ssl_err, NULL));
		set_err_string(conn, "Internal failure; please reset daemon & report");
		return -ENOTRECOVERABLE;
	}
}


/**
 * Checks to see if the given connection has an active error string.
 * @param conn The connection to check.
 * @returns 1 if an error string was found, or 0 otherwise.
 */
int has_err_string(connection* conn) {
	if (strlen(conn->err_string) > 0)
		return 1;
	else
		return 0;
}

/**
 * Sets the error string of a given connection to reflect the reason for
 * a TLS handshake failure. Note that this may return "ok" if the handshake
 * actually passed, so the verify result should be checked to ensure that 
 * it is not equal to X509_V_OK if no error string is desired on success.
 * @param conn The connection to set the error sttring for.
 * @param ssl_err The error code returned by SSL_get_verify_result().
 */
void set_verification_err_string(connection* conn, unsigned long openssl_err) {

	const char* err_description;
	long cert_err = SSL_get_verify_result(conn->ssl);
	

	if (cert_err != X509_V_OK) {
		err_description = X509_verify_cert_error_string(cert_err);

		set_err_string(conn, 
				"TLS handshake error %li: %s\n", cert_err, err_description);

		log_printf(LOG_ERROR,
				"OpenSSL verification error %li: %s\n", 
				cert_err, err_description);
    } else {
		/* an error not to do with the certificate validation */
		
		switch (ERR_GET_REASON(openssl_err)) {
		case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:
			strncpy(conn->err_string, "TLS handshake error: server supports"
					" none of the allowed ciphers\n", MAX_ERR_STRING);
			break;

		case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
			strncpy(conn->err_string, "TLS handshake error: server supports"
					" none of the allowed TLS versions\n", MAX_ERR_STRING);
			break;

		case SSL_R_UNSUPPORTED_PROTOCOL: 
			strncpy(conn->err_string, "TLS handshake error: server supports"
					" none of the allowed TLS versions\n", MAX_ERR_STRING);
			break;

		default:
			/* Add more here as needs be */
			break;
		}

	}
}

/**
 * Sets the error string for a given connection to string (plus the additional
 * arguments added in a printf-style way).
 * @param conn The connection to set an error string for.
 * @param string The printf-style string to set conn's error string to.
 */
void set_err_string(connection* conn, char* string, ...) {

	if (conn == NULL)
		return;

	va_list args;
	clear_err_string(conn);

	va_start(args, string);
	vsnprintf(conn->err_string, MAX_ERR_STRING, string, args);
	va_end(args);
}

/**
 * Clears the error string found in conn.
 * @param conn The connection to clear an error string from.
 */
void clear_err_string(connection* conn) {
	memset(conn->err_string, '\0', MAX_ERR_STRING + 1);
}

void set_badfd_err_string(connection* conn) {
	if (conn == NULL)
		return;

	clear_err_string(conn);
	strncpy(conn->err_string, "SSA daemon socket error: given socket previously"
			" failed an operation in an unrecoverable way", MAX_ERR_STRING);
}

void set_wrong_state_err_string(connection* conn) {
	if (conn == NULL)
		return;

	clear_err_string(conn);
	strncpy(conn->err_string, "SSA daemon error: given socket is not in the right "
			"state to perform the requested operation", MAX_ERR_STRING);
}


/**
 * Associates the given file descriptor with the given connection and 
 * enables its bufferevent to read and write freely.
 * @param conn The connection to have the file descriptor associated with.
 * @param ifd The file descriptor of an internal program that will
 * communicate to the daemon through plaintext.
 * @returns 0 on success, or -ECONNABORTED on failure.
 */
int associate_fd(connection* conn, evutil_socket_t ifd) {

	/* Possibility of failure is acutally none in current libevent code */
	if (bufferevent_setfd(conn->plain.bev, ifd) != 0)
		goto err;

	/* This function *unlikely* to fail, but if we want to be really robust...*/
	if (bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE) != 0)
		goto err;

	log_printf(LOG_INFO, "plaintext channel bev enabled\n");
	return 0;
 err:
	log_printf(LOG_ERROR, "associate_fd failed.\n");
	return -ECONNABORTED; /* Only happens while client is connecting */
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