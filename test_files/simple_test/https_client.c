#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

int connect_to_host(char* host, char* service);
void print_identity(int fd);

#define ERR_BUF_SIZE 256
#define RESPONSE_SIZE 5000

int main(int argc, char* argv[]) {

    char http_response[RESPONSE_SIZE];
    char http_request[2048];
    int sock_fd, ret;

    if (argc < 3) {
        //printf("USAGE: %s <host name> <port>\n", argv[0]);
        //return 0;
        char host[] = "www.google.com";
        char port[] = "443";
		
        sock_fd = connect_to_host(host, port);
        sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", host);
	} else {
        sock_fd = connect_to_host(argv[1], argv[2]);
        sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);
	}

	memset(http_response, 0, 2048);

    printf("sending info...\n");
	ret = send(sock_fd, http_request, strlen(http_request), 0);
    if (ret < 0) {
        perror("send() failed");
    } else if (send == 0) {
        printf("send() returned EOF\n");
    }

    int total_recvd = 0;
	
    printf("receiving info...\n");
    int num_recvd = recv(sock_fd, http_response, RESPONSE_SIZE, 0);
    if (num_recvd < 0) {
        perror("recv failure");
        exit(1);
    } else if (num_recvd == 0) {
        printf("recv() received EOF from server\n");
    } else {
        printf("Received:\n%s\n", http_response);
    }
	close(sock_fd);
	return 0;
}

int connect_to_host(char* host, char* service) {

	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;
	int sock, ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

        printf("Creating socket...\n");
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}

        printf("Setting hostname setsockopt...\n");
        if (setsockopt(sock, IPPROTO_TLS, TLS_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_HOSTNAME");
			close(sock);
			continue;
		}

        printf("Connecting to %s...\n", host);
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
            socklen_t len = ERR_BUF_SIZE;
            char buf[ERR_BUF_SIZE] = {0};
            int ret = getsockopt(sock, IPPROTO_TLS, TLS_ERROR, &buf, &len);
            if (ret < 0)
                perror("getsockopt on error failed");
            printf("%s\n", buf);
			close(sock);
			continue;
		}

		print_identity(sock); 
		break;
    }

	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void print_identity(int fd) {
	char data[4096];
	socklen_t data_len = sizeof(data);
	
    printf("Getting peer certificate...\n");
    if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_CERTIFICATE_CHAIN, data, &data_len) == -1) {
		perror("TLS_PEER_CERTIFICATE_CHAIN");
	}
  	printf("Peer certificate:\n%s\n", data);
    
	data_len = sizeof(data);
    printf("getting peer identity...\n");
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_IDENTITY, data, &data_len) == -1) {
		perror("TLS_PEER_IDENTITY");
	}
	printf("Peer identity:\n%s\n", data);
}

