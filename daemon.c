/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "daemon.h"
#include "tls_wrapper.h"

static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static int create_server_socket(ev_uint16_t port, int protocol);
void printf_addr(struct sockaddr *addr);

int server_create() {
	evutil_socket_t server_sock;
	struct evconnlistener* listener;
        const char* ev_version = event_get_version();
	struct event_base* ev_base = event_base_new();
	if (ev_base == NULL) {
                perror("event_base_new");
                return 1;
        }
       	printf("Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(ev_base));
	
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Start setting up server socket and event base */
	server_sock = create_server_socket(8443, SOCK_STREAM);
	listener = evconnlistener_new(ev_base, accept_cb, NULL, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) {
		perror("Couldn't crate evconnlistener");
		return 1;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(ev_base);


	/* Cleanup */
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
        event_base_free(ev_base);
        /* This function hushes the wails of memory leak
         * testing utilities, but was not introduced until
         * libevent 2.1
         */
        #if LIBEVENT_VERSION_NUMBER >= 0x02010000
        libevent_global_shutdown();
        #endif
        return 0;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;
	int optval = 1;
	struct evutil_addrinfo hints;
	struct evutil_addrinfo* addr_ptr;
	struct evutil_addrinfo* addr_list;

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* Both IPv4 and IPv6 */
	hints.ai_socktype = type;
	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = evutil_getaddrinfo(type == SOCK_DGRAM ? "::" : NULL, port_buf, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			perror("socket");
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			fprintf(stderr, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			fprintf(stderr, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			perror("bind");
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx) {
	printf("Received connection!\n");
	struct sockaddr orig_addr;
	int orig_addrlen = sizeof(struct sockaddr);
	if (getsockopt(fd, IPPROTO_IP, 86, &orig_addr, &orig_addrlen) == -1) {
		perror("getsockopt");
	}
	printf_addr(&orig_addr);
	return;
}

void accept_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "Got an error %d (%s) on the listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void printf_addr(struct sockaddr *addr) {
	/* Make sure there's enough room for IPv6 addresses */
	char str[INET6_ADDRSTRLEN];
	unsigned long ip_addr;
	struct in6_addr ip6_addr;
	int port;
	if (addr->sa_family == AF_INET) {
		ip_addr = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
		inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
		port = (int)ntohs(((struct sockaddr_in*)addr)->sin_port);
	} else {
		ip6_addr = ((struct sockaddr_in6*)addr)->sin6_addr;
		inet_ntop(AF_INET6, &ip6_addr, str, INET6_ADDRSTRLEN);
		port = (int)ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	}
	printf("%s:%d", str, port);
	return;
}

