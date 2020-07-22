#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper_functions.h"

#define MAX_HEADER_SIZE 8192
#define MAX_RESPONSE 10000
#define ERR_STRING_MAX_LEN 256


/**
 * Prints all error information available for the given socket (errno and 
 * potentially TLS_ERROR string).
 * @param fd The file descriptor to print error information for.
 */
void print_socket_error(int fd, const char* source) {

    char buf[256] = {0};
    socklen_t buf_len = 255;
    int ret;

    ret = getsockopt(fd, IPPROTO_TLS, TLS_ERROR, buf, &buf_len);
    if (ret == 0)
        fprintf(stderr, "%s failed--errno %i, err string: %s\n",
                    source, errno, buf);
    else
        fprintf(stderr, "%s failed with errno %i: %s\n", 
                    source, errno, strerror(errno));
}

/**
 * Performs `getaddrinfo()` DNS resolution on the given host and populates 
 * \p addr and \p addrlen with a viable address to connect to. The address 
 * will be an IPv4 address suitable for a TCP connection.
 * @param host The hostname to perform DNS resolution on.
 * @param addr The returned address of hostname.
 * @param addrlen The length of \p addr.
 */
int resolve_dns(const char* host, const char* port, 
            struct sockaddr** addr, socklen_t* addrlen) {

    struct addrinfo hints = {0};
    struct addrinfo* res;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) {
        printf("getaddrinfo() failed with return code %i: %s\n", 
                    ret, gai_strerror(ret));
        
        return -1;
    }

    *addr = malloc(res->ai_addrlen);
    if (*addr == NULL) {
        perror("DNS resolution failed with malloc error");
        return -1;
    }

    memcpy(*addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}



int run_http_client(const char *host, const char *port, char **out, int *out_len) {

	struct addrinfo* addr_list = NULL;
    struct addrinfo hints = {0};
    char err_str[ERR_STRING_MAX_LEN];
    socklen_t err_len = ERR_STRING_MAX_LEN;
    int error = E_UNKNOWN;
    int clientfd = -1;
    int ret;
    

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    fprintf(stderr, "Querying DNS (getaddrinfo()) to resolve hostname...\n");

    ret = getaddrinfo(host, port, &hints, &addr_list);
    if (ret != 0 || addr_list == NULL) {
        fprintf(stderr, "Getaddrinfo() returned an error\n");
        fprintf(stderr, "Errno code %i: %s\n", errno, strerror(errno));
        return E_GETADDRINFO; /* getsockopt() would be useless, so don't goto err */
    }

    fprintf(stderr, "Done.\n");
    fprintf(stderr, "Creating socket...\n");

    clientfd = socket(addr_list->ai_family, addr_list->ai_socktype, IPPROTO_TLS);
    if (clientfd < 0) {
        fprintf(stderr, "socket() returned an error\n");
        fprintf(stderr, "Errno code %i: %s\n", errno, strerror(errno));
        return E_SOCKET; /* getsockopt() would be useless, so don't goto err */
    }

    fprintf(stderr, "Done.\n");
    fprintf(stderr, "Setting hostname setsockopt()...\n");

    ret = setsockopt(clientfd, IPPROTO_TLS, 
            TLS_HOSTNAME, host, strlen(host) + 1);
    if (ret != 0) {
        fprintf(stderr, "REM_HOSTNAME setsockopt() returned an error\n");
        error = E_SETSOCKOPT;
        goto err;
    }

    fprintf(stderr, "Done.\n");
	fprintf(stderr, "Connecting to endpoint...\n");

    ret = connect(clientfd, addr_list->ai_addr, addr_list->ai_addrlen);
    if (ret != 0) {
        fprintf(stderr, "connect() returned an error\n");
        error = E_CONNECT;
        goto err;
    }

    fprintf(stderr, "Done.\n");

	freeaddrinfo(addr_list);
    close(clientfd);
    return 0;
err:

    fprintf(stderr, "Errno code %i: %s\n", errno, strerror(errno));   

    ret = getsockopt(clientfd, IPPROTO_TLS, TLS_ERROR, err_str, &err_len);
    if (ret != 0) {
        fprintf(stderr, "getsockopt() TLS_ERROR returned an error\n");
        fprintf(stderr, "Errno code %i: %s\n", errno, strerror(errno));
        error = E_NOERRORSTRING;
    } else if (err_len <= 0) {
        fprintf(stderr, "No getsockopt() TLS_ERROR was reported\n");
        error = E_NOERRORSTRING;
    } else {
        fprintf(stderr, "getsockopt() TLS_ERROR message: %s\n", err_str);
    }

    if (clientfd != -1)
        close(clientfd);
    if (addr_list != NULL)
        freeaddrinfo(addr_list);

    return error;
}
