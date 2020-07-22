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


int send_http_request(int fd, char *req, int req_len);
int recv_http_response(int fd, char **resp);
int parse_http_resp_len(char *header);

/*
int main(int argc, char **argv) {

    char *out;
    int len;

    if (argc != 3) {
        printf("Usage: ./test <hostname> <port>");
        return 1;
    }

    int ret = run_http_index_client(argv[1], argv[2], &out, &len);
    if (ret != 0) {
        printf("Failed.\n");
        return 1;
    }

    out[len] = '\0';

    printf("Output: %s\n", out);
    
    free(out);
    return 0;
}
*/

int run_client(const char *host, const char *port, 
        char *in, int in_len, char **out, int *out_len) {

    struct addrinfo* addr_list = NULL;
    struct addrinfo hints = {0};
    char err_str[ERR_STRING_MAX_LEN];
    char *response;
    socklen_t err_len = ERR_STRING_MAX_LEN;
    int clientfd = -1;
    int ret, error;

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    response = (char*) malloc(MAX_RESPONSE + 1);
    if (response == NULL) {
        fprintf(stderr, "Failed to malloc response buffer\n");
        error = E_UNKNOWN;
        goto err;
    }

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
    fprintf(stderr, "Sending http request...\n");

    ret = send_http_request(clientfd, in, in_len);
    if (ret != 0) {
        error = E_WRITE;
        goto err;
    }

    fprintf(stderr, "Done.\n");
    fprintf(stderr, "Receiving HTTP response...\n");

    ret = read(clientfd, out, MAX_RESPONSE);
    if (ret < 0) {
        error = E_READ;
        goto err;
    } else {
        *out = response;
        *out_len = ret;
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

    if (response != NULL)
        free(response);
    if (clientfd != -1)
        close(clientfd);
    if (addr_list != NULL)
        freeaddrinfo(addr_list);

    return error;
}



int run_http_client(const char *host, const char *port, char **out, int *out_len) {

	struct addrinfo* addr_list = NULL;
    struct addrinfo hints = {0};
    char err_str[ERR_STRING_MAX_LEN];
    char request[MAX_HEADER_SIZE] = {0};
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
    /*
    fprintf(stderr, "Sending http request...\n");

    ret = sprintf(request, "GET / HTTP/1.1\r\n"
                           "Connection: close\r\n"
                           "Host: %s\r\n"
                           "\r\n", host);

    ret = send_http_request(clientfd, request, strlen(request));
    if (ret != 0) {
        error = E_WRITE;
        goto err;
    }

    fprintf(stderr, "Done.\n");
    fprintf(stderr, "Receiving HTTP response...\n");

    ret = recv_http_response(clientfd, out);
    if (ret < 0) {
        error = E_READ;
        goto err;
    }
    else {
        *out_len = ret;
    }

    fprintf(stderr, "Done.\n");

    */

   *out = "Connected";
   *out_len = strlen("Connected") + 1;

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

int send_http_request(int fd, char *req, int req_len) {

    int tot_sent = 0;
    int curr_sent;

    while (tot_sent < req_len) {
        curr_sent = write(fd, req, req_len - tot_sent);
        if (curr_sent < 0) {
            fprintf(stderr, "Failed to send data to the server\n");
            return -1;
        }

        tot_sent += curr_sent;
    }

    return 0;
}

int recv_http_response(int fd, char **resp) {
    
    char buf[MAX_HEADER_SIZE + 1] = {0};
    char *response_bytes;
    int resp_len = 0;
    int tot_read = 0;
    int curr_read;

    while ((strstr(buf, "\r\n\r\n")) == NULL) {
        if (tot_read >= MAX_HEADER_SIZE) {
            fprintf(stderr, "HTTP headers were too long (max size: %i bytes)\n",
                    MAX_HEADER_SIZE);
            return -1;
        }

        curr_read = read(fd, &buf[tot_read], MAX_HEADER_SIZE - tot_read);
        if (curr_read < 0) {
            fprintf(stderr, "Failed to receive header data from the server\n");
            return -1;
        }

        tot_read += curr_read;
    }

    resp_len = parse_http_resp_len(buf);
    if (resp_len <= 0) {
        fprintf(stderr, "Failed to parse response body size\n");
        return -1;
    }

    response_bytes = (char*) malloc(resp_len + 1);
    if (response_bytes == NULL) {
        fprintf(stderr, "Failed to malloc response body\n");
        return -1;
    }

    if (tot_read > resp_len)
        tot_read = resp_len; // Truncate bytes if no Content-Length field
    memcpy(response_bytes, buf, tot_read);



    while (tot_read < resp_len) {
        curr_read = read(fd, &response_bytes[tot_read], resp_len - tot_read);
        if (curr_read < 0) {
            fprintf(stderr, "Failed to receive body data from the server\n");
            return -1;
        }

        tot_read += curr_read;
    }

    *resp = response_bytes;
    return resp_len;
}


int parse_http_resp_len(char *header) {

    long resp_len = 0;
    char *resp_body;
    char *content_length;
    int header_len;

    resp_body = strstr(header, "\r\n\r\n") + strlen("\r\n\r\n");
    header_len = (int) (resp_body - header);

    content_length = strstr(header, "Content-Length");
    if (content_length == NULL) {
        return header_len; /* no body */
    }

    content_length += strlen("Content-Length");
    while (*content_length == ' ' || *content_length == ':')
        ++content_length;
    
    resp_len = strtol(content_length, NULL, 10);
    if (resp_len < 0 || resp_len >= INT_MAX - header_len)
        return -1;

    resp_len += header_len;
    return (int) resp_len;
}