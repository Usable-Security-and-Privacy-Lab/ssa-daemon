#ifndef SSA_HELPER_FUNCTIONS_H
#define SSA_HELPER_FUNCTIONS_H

#include <sys/socket.h>
#include "../in_tls.h"

enum client_err_code {
   E_SUCCESS = 0,
   E_UNKNOWN,   
   E_GETADDRINFO,
   E_SOCKET,
   E_SETSOCKOPT,
   E_GETSOCKOPT,
   E_CONNECT,
   E_BIND,
   E_LISTEN,
   E_ACCEPT,
   E_READ,
   E_WRITE,
   E_NOERRORSTRING
};

/**
 * Prints all error information available for the given socket (errno and 
 * potentially TLS_ERROR string).
 * @param fd The file descriptor to print error information for.
 * @param source A string declaring the system call that caused the error.
 */
void print_socket_error(int fd, const char* source);




/**
 * Performs `getaddrinfo()` DNS resolution on the given host and populates 
 * \p addr and \p addrlen with a viable address to connect to. The address 
 * will be an IPv4 address suitable for a TCP connection.
 * @param host The hostname to perform DNS resolution on.
 * @param addr The returned address of hostname.
 * @param addrlen The length of \p addr.
 */
int resolve_dns(const char* host, const char* port, 
            struct sockaddr** addr, socklen_t* addrlen);


/**
 * Attempts to connect to a server specified by its hostname and port.
 * Sends all of the bytes encoded in input; the server's response is allocated
 * into output. Only one `read()` operation is performed to prevent indefinite 
 * blocking, so the server's response may be truncated.
 * @param hostname The hostname of the server to connect to 
 * (e.g. 'google.com' or 'localhost').
 * @param port The port of the server to connect to (443 = https for most)
 * @param in The sequence of bytes to send to the server.
 * @param in_len The number of bytes in `in`.
 * @param out The server's response (may be truncated).
 * @param out_len The number of bytes in `out`.
 * @returns 0 on success, or -1 if a positive code if an error occurred. 
 * The location of the error, as well as error codes and reason strings, 
 * will be printed to stderr.
 */
int run_client(const char *host, const char *port, 
        char *in, int in_len, char **out, int *out_len);


/**
 * Attempts to connect to a server specified by its hostname and port.
 * Sends an HTTP GET request for the index of the root page (/index.html).
 * The response is retrieved in full (without waiting indefinitely).
 * @param hostname The hostname of the server to connect to 
 * (e.g. 'google.com' or 'localhost').
 * @param port The port of the server to connect to (443 = https for most)
 * @param out The server's complete response to the HTTP request.
 * @param out_len The number of bytes in `out`.
 * @returns 0 on success, or -1 if an error occurred. The location of the error, 
 * as well as error codes and reason strings, will be printed to stderr.
 */
int run_http_client(const char *host, const char *port, char **out, int *out_len);













#endif