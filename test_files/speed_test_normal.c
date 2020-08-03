#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../in_tls.h"

#include "helper_functions.h"


#define HOSTNAME "localhost"


int main(int argc, char** argv) {

    unsigned long tls_context;
    socklen_t context_len = sizeof(tls_context);
    struct sockaddr* addr;
    socklen_t addrlen;
    int ret;

    if (argc != 2) {
        printf("Usage: ./speed_test_normal <number-of-connections>\n");
        exit(1);
    }

    long num_iterations = strtol(argv[1], NULL, 10);
    if (num_iterations <= 0 || num_iterations > 10000) {
        printf(" 0 < n <= 10000 is the only acceptable input\n");
        exit(1);
    }

    ret = resolve_dns(HOSTNAME, "443", &addr, &addrlen);
    if (ret != 0)
        exit(1);

    int context_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (context_fd < 0) {
        perror("context socket()");
        exit(1);
    }

    ret = setsockopt(context_fd, IPPROTO_TLS, 
                TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    if (ret < 0) {
        perror("setsockopt() for TLS_HOSTNAME");
        exit(1);
    }

    ret = getsockopt(context_fd, IPPROTO_TLS, 
                TLS_CONTEXT, &tls_context, &context_len);
    if (ret < 0) {
        perror("getsockopt() for TLS_CONTEXT");
        exit(1);
    }

    struct timeval start, stop;  
    double total_secs = 0;

    for (int i = 0; i < num_iterations; i++) {

        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
        if (fd < 0) {
            perror("socket()");
            exit(1);
        }

        ret = setsockopt(fd, IPPROTO_TLS, 
                    TLS_CONTEXT, &tls_context, sizeof(tls_context));
        if (ret < 0) {
            perror("setsockopt() on TLS_CONTEXT");
            exit(1);
        }

        gettimeofday(&start, NULL);

        ret = connect(fd, addr, addrlen);
        if (ret != 0) {
            perror("connect()");
            exit(1);
        }
        
        gettimeofday(&stop, NULL);
        total_secs += (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);
        
        /*       
        const char* request = "GET / HTTP/1.1\r\n\r\n";
        ret = send(fd, request, strlen(request)+1, 0);
        if (ret != strlen(request)+1) {
            printf("send didn't send all info\n");
            exit(1);
        }

        char resp;
        ret = recv(fd, &resp, 1, 0);
        if (ret != 1) {
            printf("recv didn't receive byte.\n");
            exit(1);
        }
            */

        close(fd);

        printf("Connection %i complete\n", i+1);
    }

    printf("time taken %f\n", total_secs); 

    close(context_fd);

    printf("Done.\n");
    return 0;
}
