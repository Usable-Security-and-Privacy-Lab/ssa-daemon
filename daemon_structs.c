
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <openssl/err.h>

#include "daemon_structs.h"
#include "log.h"


int sock_context_new(sock_context** sock_ctx, 
		daemon_context* daemon, unsigned long id) {
	
	*sock_ctx = (sock_context*)calloc(1, sizeof(sock_context));
	if (*sock_ctx == NULL)
		return -errno;

	(*sock_ctx)->daemon = daemon;
	(*sock_ctx)->id = id;
	(*sock_ctx)->fd = -1; /* standard to show not connected */
	return 0;
}

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data 
 * TODO: this function needs to be updated and debugged */
void sock_context_free(sock_context* sock_ctx) {

	if (sock_ctx == NULL) {
		log_printf(LOG_WARNING, "Tried to free a null sock_ctx reference\n");
		return;
	}

	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
	} else if (sock_ctx->fd != -1) { 
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	
	if (sock_ctx->conn != NULL)
		connection_free(sock_ctx->conn);
	free(sock_ctx);

	return;
}



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
 * Closes and frees all of the appropriate file descriptors/structs within a 
 * given sock_context. This function should be called before the connection
 * is set to a different state, as it checks the state to do particular
 * shutdown tasks. This function does not alter state.
 */
void connection_shutdown(sock_context* sock_ctx) {
	
	connection* conn = sock_ctx->conn;

	if (conn->tls != NULL) {
		switch (conn->state) {
		case CLIENT_CONNECTED:
		case SERVER_CONNECTED:
			SSL_shutdown(conn->tls);
			break;
		default:
			break;
		}
		SSL_free(conn->tls);
	}
	
	conn->tls = NULL;

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

void connection_free(connection* conn) {
	if (conn == NULL) {
		log_printf(LOG_WARNING, "Tried to free a NULL connection.\n");
		return;
	}

	if (conn->tls != NULL)
	    SSL_free(conn->tls);
	if (conn->secure.bev != NULL)
		bufferevent_free(conn->secure.bev);
	if (conn->plain.bev != NULL)
		bufferevent_free(conn->plain.bev);

	free(conn->err_string);
	free(conn);
	return;
}

/**
 * Converts a given OpenSSL ERR error code into an appropriate errno code.
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
		break;
	}

	return ENETDOWN;
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


int has_err_string(connection* conn) {
	if (strlen(conn->err_string) > 0)
		return 1;
	else
		return 0;
}

void set_verification_err_string(connection* conn, long ssl_err) {
	const char* err_description = X509_verify_cert_error_string(ssl_err);

	clear_err_string(conn);
	snprintf(conn->err_string, MAX_ERR_STRING,
			"OpenSSL verification error %li: %s\n", ssl_err, err_description);
	log_printf(LOG_ERROR,
			"OpenSSL verification error %li: %s\n", ssl_err, err_description);
}

void set_err_string(connection* conn, char* string, ...) {

	if (conn == NULL)
		return;

	va_list args;
	clear_err_string(conn);

	va_start(args, string);
	vsnprintf(conn->err_string, MAX_ERR_STRING, string, args);
	va_end(args);
}

void clear_err_string(connection* conn) {
	conn->err_string[0] = '\0';
}



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