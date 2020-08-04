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

	int opt_val;
	int opt_len = sizeof(int);
	int response;


int main(int argc, char* argv[]) {
	int sock_fd;
	char http_request[2048];
	char http_response[RESPONSE_SIZE];

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

	response = getsockopt(sock_fd, IPPROTO_TLS, TLS_VERSION_CONN, &opt_val, &opt_len);
	printf("Version should be 1.3... %s\n%d\n", tls_version_str(opt_val), opt_val);
	

	memset(http_response, 0, 2048);
	send(sock_fd, http_request, strlen(http_request), 0);
    int total_recvd = 0;
	
    int num_recvd = recv(sock_fd, http_response, RESPONSE_SIZE, 0);
    if (num_recvd < 0) {
        perror("recv failure");
        exit(1);
    } else if (num_recvd == 0) {
        printf("NOTE: Client received EOF from server.\n");
    } else {
        printf("Received:\n%s\n", http_response);
    }
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
	if (addr_list == NULL)
		fprintf(stderr, "That isn't supposed to happen.\n");

	fprintf(stderr, "ai_addr: %d\nai_addrlen: %d\n", addr_list->ai_addr, addr_list->ai_addrlen);
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		fprintf(stderr, "sock: %d\n", sock);
		if (sock == -1) {
			perror("socket");
			continue;
		}

	        if (setsockopt(sock, IPPROTO_TLS, TLS_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock);
			continue;
		}

	int opt_val = TLS_1_3;
	int opt_len = sizeof(int);
	int response;

	getsockopt(sock, IPPROTO_TLS, TLS_VERSION_MIN, &opt_val, &opt_len);
	printf("Version should be 1.2... %s\n", tls_version_str(opt_val)); 

	opt_val = TLS_1_3;
	response = setsockopt(sock, IPPROTO_TLS, TLS_VERSION_MIN, &opt_val, opt_len);
	if (response)
		fprintf(stderr, "%s\n", strerror(errno));
	getsockopt(sock, IPPROTO_TLS, TLS_VERSION_MIN, &opt_val, &opt_len);
	printf("Version should be 1.3... %s\n", tls_version_str(opt_val));

	opt_val = TLS_1_2;
	response = setsockopt(sock, IPPROTO_TLS, TLS_VERSION_MAX, &opt_val, opt_len);
	if (response)
		fprintf(stderr, "%s\n", strerror(errno));

	getsockopt(sock, IPPROTO_TLS, TLS_VERSION_MAX, &opt_val, &opt_len);
	printf("Version should be 1.3... %s\n", tls_version_str(opt_val));

		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
            socklen_t len = ERR_BUF_SIZE;
            char buf[ERR_BUF_SIZE] = {0};
            int ret = getsockopt(sock, IPPROTO_TLS, TLS_ERROR, &buf, &len);
            if (ret < 0)
                perror("setsockopt on error failed");
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
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_CERTIFICATE_CHAIN, data, &data_len) == -1) {
		perror("TLS_PEER_CERTIFICATE_CHAIN");
	}
  	printf("Peer certificate:\n%s\n", data);
    
	data_len = sizeof(data);
	if (getsockopt(fd, IPPROTO_TLS, TLS_PEER_IDENTITY, data, &data_len) == -1) {
		perror("TLS_PEER_IDENTITY");
	}
	printf("Peer identity:\n%s\n", data);
	
}

