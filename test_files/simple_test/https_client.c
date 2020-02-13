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

int main(int argc, char* argv[]) {
	int sock_fd;
	char http_request[2048];
	char http_response[2048];

	if (argc < 3) {
		printf("USAGE: %s <host name> <port>\n", argv[0]);
		return 0;
	}

	sock_fd = connect_to_host(argv[1], argv[2]);
	sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);

	memset(http_response, 0, 2048);
	send(sock_fd, http_request, strlen(http_request), 0);
	recv(sock_fd, http_response, 750, 0);
	printf("Received:\n%s\n", http_response);
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
		printf("Trying next address in address list\n");
		sock = socket(PF_INET, SOCK_STREAM,/*addr_ptr->ai_family, addr_ptr->ai_socktype,*/ IPPROTO_TLS); //changed to match other test file's configuration which doesn't have this problem
		if (sock == -1) {
			perror("socket");
			continue;
		}
			//a comment on the other https_client file says that this line only applies to TLS sockets, which this is, but it fails to allocate a buffer for TLS_REMOTE_HOSTNAME. This buffer appears to be necessary in order for certificate validation to occur.
	        if (setsockopt(sock, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) { //this line fails because TLS_REMOTE_HOSTNAME has no buffer space available, even when compiled with the argument hostname-support
			printf(host);
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
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
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_CERTIFICATE_CHAIN, data, &data_len) == -1) {
		perror("TLS_PEER_CERTIFICATE_CHAIN");
	}
	printf("Peer certificate:\n%s\n", data);
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_IDENTITY, data, &data_len) == -1) {
		perror("TLS_PEER_IDENTITY");
	}
	printf("Peer identity:\n%s\n", data);
	return;
}

