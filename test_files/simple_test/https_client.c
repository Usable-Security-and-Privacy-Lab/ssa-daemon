#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define HOST "www.google.com"

int connect_to_host(char* host, char* service);
void print_identity(int fd);

int main() {
	int sock_fd = connect_to_host(HOST, "443");
	char http_request[2048];
	char http_response[2048];
	sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", HOST);
	memset(http_response, 0, 2048);
	send(sock_fd, http_request, sizeof(http_request)-1, 0);
	recv(sock_fd, http_response, 750, 0);
	printf("Received:\n%s", http_response);
	close(sock_fd);
	return 0;
}

int connect_to_host(char* host, char* service) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
	        if (setsockopt(sock, IPPROTO_TLS, SO_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: SO_REMOTE_HOSTNAME");
			close(sock);
			continue;
		}

		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
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
	if (getsockopt(fd, IPPROTO_TLS, SO_PEER_CERTIFICATE, data, &data_len) == -1) {
		perror("SO_PEER_CERTIFICATE");
	}
	printf("Peer certificate:\n%s\n", data);
	if (getsockopt(fd, IPPROTO_TLS, SO_PEER_IDENTITY, data, &data_len) == -1) {
		perror("SO_PEER_IDENTITY");
	}
	printf("Peer identity:\n%s\n", data);
	return;
}

