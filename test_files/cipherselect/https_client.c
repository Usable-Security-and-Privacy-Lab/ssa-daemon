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

#define RESPONSE_SIZE 5000

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
      //  printf("Received:\n%s\n", http_response);
			printf("Received successfully\n");
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

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
	  if (setsockopt(sock, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock);
			continue;
		}

		char cipher[] = "TLS_AES_256_GCM_SHA384";
		char cipher1[] = "ECDHE-RSA-AES256-GCM-SHA384";
		char bad_cipher[] = "NULL-SHA256";
		char old_cipher[] = "EDH-DSS-DES-CBC3-SHA";
		char two_12ciphers[] = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
		char two_ciphers[] = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
		char good_and_bad[] = "NULL-MD5:ECDHE-RSA-AES256-GCM-SHA384";

		if (setsockopt(sock, IPPROTO_TLS, TLS_DISABLE_CIPHER, cipher1, strlen(cipher1)+1) == -1) {
      perror("setsockopt: TLS_DISABLE_CIPHER");
      //close(sock);
      continue;
    }

    if (setsockopt(sock, IPPROTO_TLS, TLS_ENABLE_CIPHER, cipher1, strlen(cipher1) + 1) == -1) {
      perror("setsockopt: TLS_ENABLE_CIPHER");
      //close(sock);
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
  	//printf("Peer certificate:\n%s\n", data);

	data_len = sizeof(data);
	data[0] = '\0'; //empty
  if (getsockopt(fd, IPPROTO_TLS, TLS_TRUSTED_CIPHERS, data, &data_len) == -1) {
		perror("TLS_TRUSTED_CIPHERS");
	}
	printf("Trusted ciphers:\n%s\n", data);
	data_len = sizeof(data);
	char data1[200];
	socklen_t data_len1 = sizeof(data1);
  if (getsockopt(fd, IPPROTO_TLS, TLS_CHOSEN_CIPHER, data1, &data_len1) == -1) {
		perror("TLS_CHOSEN_CIPHER");
	}
	data[data_len] = '\0';
	printf("Negotiated cipher:\n%s\n Length: %d", data1, data_len1);

}
