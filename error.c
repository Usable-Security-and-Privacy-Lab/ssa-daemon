#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "error.h"
#include "log.h"


void set_badfd_err_string(socket_ctx* sock_ctx);
void set_wrong_state_err_string(socket_ctx* sock_ctx);


/**
 * Checks to see if the given socket has an active error string.
 * @param sock_ctx The context of the socket to check.
 * @returns 1 if an error string was found, or 0 otherwise.
 */
int has_error_string(socket_ctx* sock_ctx) {
	if (strlen(sock_ctx->err_string) > 0)
		return 1;
	else
		return 0;
}



/**
 * Checks the OpenSSL error queue and converts the error into an errno code.
 * @returns A negative errno code.
 */
int determine_errno_error() {

    unsigned long ssl_err = ERR_peek_error();
    const char* err_string = ERR_error_string(ssl_err, NULL);

    if (ERR_GET_REASON(ssl_err) == ERR_R_MALLOC_FAILURE) {
        return -ENOMEM;

    } else {
        log_printf(LOG_ERROR, "Internal daemon error: %s\n", err_string);
        return -ECANCELED;
    }
}


/**
 * Determines the nature of the error that has occured on the socket, and 
 * then sets that socket's error string (and optionally error code).
 * @param sock_ctx The context of the socket to set an error for.
 * @returns 0 if no error report could be found, or a negative errno code
 * (such as EPROTO for handshake protocol errors or ENOMEM when out of memory).
 */
int determine_and_set_error(socket_ctx* sock_ctx) {

    return set_socket_error(sock_ctx, ERR_get_error());
}


/**
 * Sets the error string (and optionally error code) for the given socket.
 * If a certificate verification is reported, it will be prioritized above
 * the ssl_err passed in.
 * @param sock_ctx The context of the socket to set an error code for.
 * @param ssl_err The OpenSSL error code to decipher and produce an error from.
 * @returns 0 if no error could be found, or a negative errno code that can 
 * be returned to the user for a given system call.
 */
int set_socket_error(socket_ctx* sock_ctx, unsigned long ssl_err) {

    long handshake_err = SSL_get_verify_result(sock_ctx->ssl);
    const char* verify_str = X509_verify_cert_error_string(handshake_err);

    clear_socket_error(sock_ctx);

    /* first, check to see if there is a verification error */
    switch(handshake_err) {
    case X509_V_OK:
        break; /* we need to use the ssl_err instead */

    case X509_V_ERR_OUT_OF_MEM:
        return -ENOMEM;

    default:
        sock_ctx->handshake_err_code = handshake_err;
        set_err_string(sock_ctx, "TLS handshake error %li: %s", 
                    handshake_err, verify_str);
        return -EPROTO;
    }

    /* If that didn't work, we'll use the ssl_err code */
    if (ssl_err == NO_ERROR)
        return 0;

    int error_library = ERR_GET_LIB(ssl_err);
    int error_reason = ERR_GET_REASON(ssl_err);
    const char* reason_str = ERR_reason_error_string(ssl_err);

    if (error_reason == ERR_R_MALLOC_FAILURE)
        return -ENOMEM;

    if (error_library == ERR_LIB_SSL) {

        switch(error_reason) {
        case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:
            set_err_string(sock_ctx, "TLS handshake failure: peer sent alert"
                        " (likely no common TLS version or ciphersuites)");
            break;

        default:
            set_err_string(sock_ctx, "TLS handshake failure: %s", reason_str);
        }

        return -EPROTO;
    }

    set_err_string(sock_ctx, "Internal daemon error: check logs for details");
    log_printf(LOG_ERROR, "Internal daemon error during handshake: %s\n", 
                ERR_error_string(ssl_err, NULL));


    if (sock_ctx->state == SOCKET_CONNECTING 
                || sock_ctx->state == SOCKET_FINISHING_CONN) 
        return -ECONNABORTED;
    else 
        return -ECANCELED; /* system call canceled due to daemon error */
        /* OR return -EUNRECOVERABLE; */
}


/**
 * Sets the error string for a given socket to string (plus the additional
 * arguments added in a printf-style way).
 * @param sock_ctx The context of the socket to set an error string for.
 * @param string The printf-style string to set sock_ctx's error string to.
 */
void set_err_string(socket_ctx* sock_ctx, char* string, ...) {

    int error = errno;

	if (sock_ctx == NULL)
		return;

	va_list args;
	clear_socket_error(sock_ctx);

	va_start(args, string);
	vsnprintf(sock_ctx->err_string, MAX_ERR_STRING, string, args);
	va_end(args);

    errno = error;
}



void log_global_error(enum log_level level, char *message) {

    char *error_string;

    if (errno != 0)
        error_string = strerror(errno);
    else
        error_string = ERR_reason_string(ERR_get_error());

    log_printf(level, "%s: %s\n", message, error_string);

    clear_global_errors();
}



/**
 * Clears the OpenSSL error queue and any error recorded in errno.
 */
void clear_global_errors() {

    ERR_clear_error();
    errno = NO_ERROR;
}


/**
 * Clears the error string and verification error code found in sock_ctx.
 * @param sock_ctx The context of the socket to clear error information from.
 * @note This function does not modify the state of the given socket.
 */
void clear_socket_error(socket_ctx* sock_ctx) {

	memset(sock_ctx->err_string, 0, MAX_ERR_STRING + 1);
    sock_ctx->handshake_err_code = NO_ERROR;
}


/**
 * Clears the error string and verification error code found in sock_ctx, 
 * as well as the OpenSSL error queue and any error recorded in errno.
 * @param sock_ctx The context of the socket to clear error information from.
 * @note This function does not modify the state of the given socket.
 */
void clear_global_and_socket_errors(socket_ctx* sock_ctx) {

    clear_global_errors();
    clear_socket_error(sock_ctx);
}



void set_badfd_err_string(socket_ctx* sock_ctx) {
	if (sock_ctx == NULL)
		return;

    set_err_string(sock_ctx, "SSA daemon socket error: given socket "
                "previously failed an operation in an unrecoverable way");
}


void set_wrong_state_err_string(socket_ctx* sock_ctx) {
	if (sock_ctx == NULL)
		return;

	set_err_string(sock_ctx, "SSA daemon error: given socket is not in the "
                "right state to perform the requested operation");
}