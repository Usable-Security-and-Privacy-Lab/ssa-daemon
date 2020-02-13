#define _GNU_SOURCE

#include <dlfcn.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "../in_tls.h"
#include "stdio.h"

#define PORT_LENGTH	32
char* custom_itoa(int num, char* buf, int len);

/* This POC is IPv4 only but can easily be extended to do IPv6 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	typeof(connect) *real_connect;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;
	struct sockaddr_host* host_addr;
	char* hostname;
	char service[PORT_LENGTH];
	int ret;
	int type;
	int type_len;

	printf("Connect overriden\n");

	/* Determine location of original connect call */
	real_connect = dlsym(RTLD_NEXT, "connect");

	printf("dlsym found runtime address of connect() at %p\n", real_connect);

	if (addr->sa_family != AF_HOSTNAME) {
		printf("Hostname already resolved, going straight to system call\n");
		return (*real_connect)(sockfd, addr, addrlen);
	}

	printf("Address family has been detected as AF_HOSTNAME\n");

	/* Determine socket type */
	type_len = sizeof(type);
	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &type_len) == -1) {
		errno = EPROTOTYPE;
		return -1;
	}


	/* Set hostname (only works on TLS sockets, so we check retval) */
	host_addr = (struct sockaddr_host*)addr;

	hostname = host_addr->sin_addr.name;
	setsockopt(sockfd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, hostname, strlen(hostname)+1);	//This fails on the other https_client test

	/* Resolve hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = type;
	hints.ai_family = AF_INET; /* Set AF_UNSPEC for IPv6 and IPv4 */
	custom_itoa(ntohs(host_addr->sin_port), service, PORT_LENGTH);

	printf("Calling getaddrinfo\n");

	ret = getaddrinfo(hostname, service, &hints, &addr_list);
	if (ret != 0) {
		errno = EHOSTUNREACH;
		fprintf(stderr, "getaddrinfo failed");
		return -1;
	}

	printf("getaddrinfo returned linked list of addresses\n");

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

		//next few lines for debugging
		struct sockaddr_in *readableSockaddr = (struct sockaddr_in *) addr_ptr->ai_addr;
		char *addrString = malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(readableSockaddr->sin_addr), addrString, INET_ADDRSTRLEN);
		//do I need to call ntohs on sin_port? It causes segfault when I do...
		printf("Trying next entry in address array: %s:%hu\n", addrString, ntohs(readableSockaddr->sin_port));//returns port 47873, which always hangs until time out even in my browser

		free(addrString);
		addrString = NULL;
		//

		int test = (*real_connect)(sockfd, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		printf("Result of real connect(): %i\n", test);
		if (test == 0) {
			printf("Connection made\n");
			return 0; /* Success */
		}
	}

	printf("Entire list of connections failed\n");
	freeaddrinfo(addr_list);
	return -1;
}


char* custom_itoa(int num, char* buf, int len) {
	if (buf == NULL) {
		return NULL;
	}
	snprintf(buf, len, "%d", num);
	return buf;
}

