#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define CERT_FILE "../certs/server_chain.pem"
#define KEY_FILE  "../certs/server_key.pem"
#define BUFFER_SIZE    2048

void handle_req(char* req, char* resp, int num_received);

int main() {
    char servername[255];
    int servername_len = sizeof(servername);
    int ret;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    memset(request, 0, BUFFER_SIZE);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(4433);

    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) {
        perror("socket() failed");
        exit(1);
    }

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0) {
        perror("bind() failed");
        exit(1);
    }

    ret = setsockopt(fd, IPPROTO_TLS, 
                TLS_CERTIFICATE_CHAIN, CERT_FILE, strlen(CERT_FILE)+1);
    if (ret < 0) {
        perror("TLS_CERTIFICATE_CHAIN setsockopt() failed");
        exit(1);
    }

    ret = setsockopt(fd, IPPROTO_TLS, 
                TLS_PRIVATE_KEY, KEY_FILE, strlen(KEY_FILE)+1);
    if (ret < 0) {
        perror("TLS_PRIVATE_KEY setsockopt() failed");
        exit(1);
    }

    
    ret = listen(fd, SOMAXCONN);
    if (ret < 0) {
        perror("listen() failed");
        exit(1);
    }

    while (1) {    
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
        if (c_fd < 0 && errno == ECONNABORTED) {
            printf("connection dropped\n");
            continue;
        }

        printf("Connection received!\n");
        int num_received = recv(c_fd, request, BUFFER_SIZE, 0);
        if(num_received < 0) {
            printf("Errno on recv: %s\n", strerror(errno));
            close(c_fd);
            return -1;
        } else if (num_received == 0) {
            printf("Connection closed.\n");
            close(c_fd);
            continue;
        }

        printf("Received %i bytes from client.\n", num_received);
        handle_req(request, response, num_received);
        int num_sent = send(c_fd, response, num_received+1, 0); /* +1 for EOF */
        printf("Sent %i bytes to client.\n", num_sent);
        close(c_fd);
    }
    return 0;
}

void handle_req(char* req, char* resp, int num_received) {
    memcpy(resp, req, num_received);
    resp[num_received] = '\0';
    return;
}
