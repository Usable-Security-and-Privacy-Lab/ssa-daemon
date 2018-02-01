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
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "daemon.h"
#include "hashmap.h"
#include "tls_wrapper.h"
#include "netlink.h"
#include "log.h"

/* XXX These should really be linked with
 * the socktls.h file from the other repo */
#define SO_HOSTNAME		85
#define SO_PEER_CERTIFICATE	86
#define SO_CERTIFICATE_CHAIN	87
#define SO_PRIVATE_KEY		88
#define SO_ID			89


#define MAX_HOSTNAME		255
#define HASHMAP_NUM_BUCKETS	100

typedef struct sock_ctx {
	unsigned long id;
	evutil_socket_t fd;
	int has_bound; /* Nonzero if we've called bind locally */
	struct sockaddr int_addr;
	int int_addrlen;
	union {
		struct sockaddr ext_addr;
		struct sockaddr rem_addr;
	};
	union {
		int ext_addrlen;
		int rem_addrlen;
	};
	int is_connected;
	int is_accepting;
	struct evconnlistener* listener;
	SSL_CTX* tls_ctx;
	char hostname[MAX_HOSTNAME];
	tls_conn_ctx_t* tls_conn;
} sock_ctx_t;

void free_sock_ctx(sock_ctx_t* sock_ctx);

/* SSA client functions */
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void signal_cb(evutil_socket_t fd, short event, void* arg);
static evutil_socket_t create_server_socket(ev_uint16_t port, int family, int protocol);

/* SSA server functions */
static void server_accept_error_cb(struct evconnlistener *listener, void *ctx);
static void server_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg);

/* special */
static evutil_socket_t create_upgrade_socket(void);
static void upgrade_recv(evutil_socket_t fd, short events, void *arg);
ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes, int *recvfd, struct sockaddr_un* addr, int addr_len);

int server_create(int port) {
	int ret;
	evutil_socket_t server_sock;
	evutil_socket_t upgrade_sock;
	struct evconnlistener* listener;

        const char* ev_version = event_get_version();
	struct event_base* ev_base = event_base_new();
	struct event* sev_pipe;
	struct event* sev_int;
	struct event* nl_ev;
	struct event* upgrade_ev;
	struct nl_sock* netlink_sock;
	if (ev_base == NULL) {
                perror("event_base_new");
                return 1;
        }

       	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(ev_base));
	
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Signal handler registration */
	sev_pipe = evsignal_new(ev_base, SIGPIPE, signal_cb, NULL);
	if (sev_pipe == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGPIPE handler event");
		return 1;
	}
	sev_int = evsignal_new(ev_base, SIGINT, signal_cb, ev_base);
	if (sev_int == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGINT handler event");
		return 1;
	}
	evsignal_add(sev_pipe, NULL);
	evsignal_add(sev_int, NULL);

	//signal(SIGPIPE, SIG_IGN);

	tls_daemon_ctx_t daemon_ctx = {
		.ev_base = ev_base,
		.netlink_sock = NULL,
		.port = port,
		.sock_map = hashmap_create(HASHMAP_NUM_BUCKETS),
		.sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS),
	};

	/* Set up server socket with event base */
	server_sock = create_server_socket(port, PF_INET, SOCK_STREAM);
	listener = evconnlistener_new(ev_base, accept_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create evconnlistener");
		return 1;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Set up netlink socket with event base */
	netlink_sock = netlink_connect(&daemon_ctx);
	if (netlink_sock == NULL) {
		log_printf(LOG_ERROR, "Couldn't create Netlink socket");
		return 1;
	}
	ret = evutil_make_socket_nonblocking(nl_socket_get_fd(netlink_sock));
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	nl_ev = event_new(ev_base, nl_socket_get_fd(netlink_sock), EV_READ | EV_PERSIST, netlink_recv, netlink_sock);
	if (event_add(nl_ev, NULL) == -1) {
		log_printf(LOG_ERROR, "Couldn't add Netlink event");
		return 1;
	}

	/* Set up upgrade notification socket with event base */
	if (port == 8443) {
		upgrade_sock = create_upgrade_socket();
		upgrade_ev = event_new(ev_base, upgrade_sock, EV_READ | EV_PERSIST, upgrade_recv, &daemon_ctx);
		if (event_add(upgrade_ev, NULL) == -1) {
			log_printf(LOG_ERROR, "Couldn't add upgrade event");
			return 1;
		}
	}

	/* Main event loop */	
	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "Main event loop terminated\n");
	netlink_disconnect(netlink_sock);

	/* Cleanup */
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	hashmap_free(daemon_ctx.sock_map_port);
	hashmap_deep_free(daemon_ctx.sock_map, (void (*)(void*))free_sock_ctx);
	event_free(nl_ev);
	if (port == 8443) {
		event_free(upgrade_ev);
	}
	event_free(sev_pipe);
	event_free(sev_int);
        event_base_free(ev_base);
        /* This function hushes the wails of memory leak
         * testing utilities, but was not introduced until
         * libevent 2.1
         */
        #if LIBEVENT_VERSION_NUMBER >= 0x02010000
        libevent_global_shutdown();
        #endif

	/* Standard OpenSSL cleanup functions */
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_cleanup();
	#else
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	SSL_COMP_free_compression_methods();
	#endif
        return 0;
}

evutil_socket_t create_upgrade_socket(void) {
	evutil_socket_t sock;
	int ret;
	struct sockaddr_un addr;
	int addrlen;
	char name[] = "\0tls_upgrade";
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, "\0tls_upgrade", sizeof(name));
	addrlen = sizeof(name) + sizeof(sa_family_t);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	ret = evutil_make_socket_nonblocking(sock);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}

	ret = bind(sock, (struct sockaddr*)&addr, addrlen);
	if (ret == -1) {
		log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}
	return sock;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;
	int optval = 1;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo* addr_ptr;
	struct evutil_addrinfo* addr_list;
	struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
	};

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

	if (family == PF_UNIX) {
		sock = socket(AF_UNIX, type, 0);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		strcpy(bind_addr.sun_path+1, port_buf);
		ret = bind(sock, (struct sockaddr*)&bind_addr, sizeof(sa_family_t) + 1 + strlen(port_buf));
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}
		return sock;
	}

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
		log_printf(LOG_ERROR, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1) {
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		log_printf(LOG_ERROR, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	log_printf(LOG_INFO, "Received connection!\n");

	int port;
	sock_ctx_t* sock_ctx;
	tls_daemon_ctx_t* ctx = arg;

	if (address->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)address)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)address)->sin_port);
	}
	sock_ctx = hashmap_get(ctx->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Got an unauthorized connection on port %d\n", port);
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	log_printf_addr(&sock_ctx->rem_addr);

	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	log_printf(LOG_INFO, "Hostname: %s (%p)\n", sock_ctx->hostname, sock_ctx->hostname);
	hashmap_del(ctx->sock_map_port, port);
	//hashmap_del(ctx->sock_map, sock_ctx->id);
	if (sock_ctx->is_accepting == 0) {
		sock_ctx->tls_conn = tls_client_wrapper_setup(fd, sock_ctx->fd, ctx->ev_base, sock_ctx->hostname, 0);
	}
	else {
		sock_ctx->tls_conn = tls_client_wrapper_setup(fd, sock_ctx->fd, ctx->ev_base, sock_ctx->hostname, 1);
	}
	//free(sock_ctx);
	return;
}

void accept_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void server_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	sock_ctx_t* sock_ctx = (sock_ctx_t*)arg;
        struct event_base *base = evconnlistener_get_base(listener);
	log_printf(LOG_DEBUG, "Got a connection on a vicarious listener\n");
	log_printf_addr(&sock_ctx->int_addr);
	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(fd);
		return;
	}
	sock_ctx->tls_conn = tls_server_wrapper_setup(fd, base, sock_ctx->tls_ctx, 
			&sock_ctx->int_addr, sock_ctx->int_addrlen);
	return;
}

void server_accept_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on a server listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void signal_cb(evutil_socket_t fd, short event, void* arg) {
	int signum = fd; /* why is this fd? */
	switch (signum) {
		case SIGPIPE:
			log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
			break;
		case SIGINT:
			log_printf(LOG_DEBUG, "Caught SIGINT\n");
			event_base_loopbreak(arg);
			break;
		default:
			break;
	}
	return;
}

void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id) {
	sock_ctx_t* sock_ctx;
	evutil_socket_t fd;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx != NULL) {
		log_printf(LOG_ERROR, "We have created a socket with this ID already: %lu\n", id);
		netlink_notify_kernel(ctx, id, response);
		return;
	}

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		response = -errno;
	}
	else {
		sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
		if (sock_ctx == NULL) {
			response = -ENOMEM;
		}
		else {
			sock_ctx->id = id;
			sock_ctx->fd = fd;
			hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, 
		int option, void* value, socklen_t len) {
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		netlink_notify_kernel(ctx, id, response);
		return;
	}
	switch (option) {
		case SO_HOSTNAME:
			/* The kernel validated this data for us */
			memcpy(sock_ctx->hostname, value, len);
			log_printf(LOG_INFO, "Assigning %s to socket %lu\n",
					sock_ctx->hostname, id);
			set_hostname(sock_ctx->tls_conn, sock_ctx->hostname);
			ret = 0; /* Success */
			break;
		case SO_CERTIFICATE_CHAIN:
			if (set_certificate_chain(sock_ctx->tls_ctx, value) == 0) {
				response = -EBADF;
				netlink_notify_kernel(ctx, id, response);
			}
			ret = 0;
			break;
		case SO_PRIVATE_KEY:
			if (set_private_key(sock_ctx->tls_ctx, value) == 0) {
				response = -EBADF;
				netlink_notify_kernel(ctx, id, response);
			}
			ret = 0;
			break;
		default:
			ret = setsockopt(sock_ctx->fd, level, option, value, len);
			break;
	}
	if (ret == -1) {
		response = -errno;
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void getsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, int option) {
	sock_ctx_t* sock_ctx;
	char* data = NULL;
	unsigned int len = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(ctx, id, -EBADF);
		return;
	}
	switch (option) {
		case SO_PEER_CERTIFICATE:
			if (sock_ctx->tls_conn == NULL) {
				netlink_notify_kernel(ctx, id, -ENOTCONN);
				return;
			}
			data = get_peer_certificate(sock_ctx->tls_conn, &len);
			if (data == NULL) {
				netlink_notify_kernel(ctx, id, -ENOTCONN);
				return;
			}
			netlink_send_and_notify_kernel(ctx, id, data, len);
			free(data);
			return;
		default:
			log_printf(LOG_ERROR, "Default case for getsockopt hit: should never happen\n");
			netlink_notify_kernel(ctx, id, -EBADF);
			return;
	}
	return;
}

void bind_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {

	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		ret = bind(sock_ctx->fd, ext_addr, ext_addrlen);
		if (ret == -1) {
			perror("bind");
			response = -errno;
		}
		else {
			sock_ctx->has_bound = 1;
			sock_ctx->int_addr = *int_addr;
			sock_ctx->int_addrlen = int_addrlen;
			sock_ctx->ext_addr = *ext_addr;
			sock_ctx->ext_addrlen = ext_addrlen;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void connect_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen) {
	
	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	int port;

	if (int_addr->sa_family == AF_UNIX) {
		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
		log_printf(LOG_INFO, "unix port is %05x", port);
	}
	else {
		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
	}

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		/* only connect if we're not already.
		 * we might already be connected due to a
		 * socket upgrade */
		if (sock_ctx->is_connected == 0) {
			ret = connect(sock_ctx->fd, rem_addr, rem_addrlen);
		}
		else {
			ret = 0;
		}
		if (ret == -1) {
			response = -errno;
		}
		else {
			if (sock_ctx->has_bound == 0) {
				sock_ctx->int_addr = *int_addr;
				sock_ctx->int_addrlen = int_addrlen;
			}
			log_printf(LOG_INFO, "Placing sock_ctx for port %d\n", port);
			hashmap_add(ctx->sock_map_port, port, sock_ctx);
			sock_ctx->rem_addr = *rem_addr;
			sock_ctx->rem_addrlen = rem_addrlen;
			sock_ctx->is_connected = 1;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	return;
}

void listen_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {

	int ret;
	sock_ctx_t* sock_ctx;
	int response = 0;
	
	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
	}
	else {
		ret = listen(sock_ctx->fd, SOMAXCONN);
		if (ret == -1) {
			response = -errno;
		}
	}
	netlink_notify_kernel(ctx, id, response);
	if (response != 0) {
		return;
	}
	
	/* We're done gathering info, let's set up a server */
	ret = evutil_make_listen_socket_reuseable(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
		return;
	}

	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
		return;
	}

	sock_ctx->tls_ctx = tls_server_ctx_create();
	sock_ctx->listener = evconnlistener_new(ctx->ev_base, server_accept_cb, sock_ctx,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->fd);

	evconnlistener_set_error_cb(sock_ctx->listener, server_accept_error_cb);
	return;
}

void close_cb(tls_daemon_ctx_t* ctx, unsigned long id) {
	int ret;
	sock_ctx_t* sock_ctx;

	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		return;
	}
	/* close things here */
	if (sock_ctx->is_accepting == 1) {
		/* This is an ophan server connection.
		 * We don't host its corresponding listen socket
		 * But we were given control of the remote peer
		 * connection */
		hashmap_del(ctx->sock_map, id);
		SSL_CTX_free(sock_ctx->tls_ctx);
		free(sock_ctx);
		return;
	}
	if (sock_ctx->is_connected == 1) {
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
		//netlink_notify_kernel(ctx, id, 0);
		hashmap_del(ctx->sock_map, id);
		free(sock_ctx);
		return;
	}
	if (sock_ctx->listener != NULL) {
		hashmap_del(ctx->sock_map, id);
		evconnlistener_free(sock_ctx->listener);
		SSL_CTX_free(sock_ctx->tls_ctx);
		free(sock_ctx);
		//netlink_notify_kernel(ctx, id, 0);
		return;
	}
	hashmap_del(ctx->sock_map, id);
	EVUTIL_CLOSESOCKET(sock_ctx->fd);
	free(sock_ctx);
	//netlink_notify_kernel(ctx, id, 0);
	return;
}

void upgrade_cb(tls_daemon_ctx_t* ctx, unsigned long id, 
		struct sockaddr* int_addr, int int_addrlen) {
	int port;
	int fd = (int)id; /* the ID is actually the new socket descriptor */
	port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);

	/* XXX To make this function work we need:
	 * 	1) daemon's fd for old existing socket connection
	 * 	2) kernel socket pointer (ID) for new socket created for app
	 * 	3) port to which new socket created for app is bound (and we need to bind it too)
	 * 	4) information on whether or not this socket is passive or active (has listen() been called?)
	 * 	5) if socket is active but NOT a server socket (SSL_accept case)...we need to know this
	 */
	return;
}

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data */
void free_sock_ctx(sock_ctx_t* sock_ctx) {
	if (sock_ctx->listener != NULL) {
		evconnlistener_free(sock_ctx->listener);
		SSL_CTX_free(sock_ctx->tls_ctx);
	}
	else if (sock_ctx->is_connected == 1) {
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
	}
	else {
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	free(sock_ctx);
	return;
}

void upgrade_recv(evutil_socket_t fd, short events, void *arg) {
	sock_ctx_t* sock_ctx;
	tls_daemon_ctx_t* ctx = (tls_daemon_ctx_t*)arg;
	char msg_buffer[256];
	int new_fd;
	int bytes_read;
	unsigned long id;
	int is_accepting;
	struct sockaddr_un addr = {};
	/* Why the 5? Because that's what linux uses for autobinds*/
	/* Why the 1? Because of the null byte in front of abstract names */
	int addr_len = sizeof(sa_family_t) + 5 + 1;
	log_printf(LOG_INFO, "Someone wants an upgrade!\n");
	memset(msg_buffer, 0, 256);
	bytes_read = recv_fd_from(fd, msg_buffer, 255, &new_fd, &addr, addr_len);
	if (bytes_read == -1) {
		log_printf(LOG_ERROR, "recv_fd: %s\n", strerror(errno));
		return;
	}

	sscanf(msg_buffer, "%d:%lu", &is_accepting, &id);
	log_printf(LOG_INFO, "Got a new %s descriptor %d, to be associated with %lu from addr %s\n",
		       	is_accepting == 1 ? "accepting" : "connecting", new_fd, id, addr.sun_path+1, addr_len);
	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		return;
	}
	EVUTIL_CLOSESOCKET(sock_ctx->fd);
	sock_ctx->fd = new_fd;
	sock_ctx->is_connected = 1;

	if (is_accepting == 1) {
		sock_ctx->tls_ctx = tls_server_ctx_create();
		sock_ctx->is_accepting = 1;
	}

	if (sendto(fd, "GOT IT", sizeof("GOT IT"), 0, &addr, addr_len) == -1) {
		perror("sendto");
	}
	return;
}

/* Modified read_fd taken from various online sources. Found without copyright or
 * attribution. Examples also in manpages so we could use that if needed */
ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes, int *recvfd, struct sockaddr_un* addr, int addr_len) {
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t	n;
	int newfd;

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr* cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);
	msg.msg_name = addr;
	msg.msg_namelen = addr_len;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ((n = recvmsg(fd, &msg, 0)) <= 0) {
		return n;
	}

	if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
	    cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET) {
			log_printf(LOG_ERROR, "control level != SOL_SOCKET\n");
			return -1;
		}
		if (cmptr->cmsg_type != SCM_RIGHTS) {
			log_printf(LOG_ERROR, "control type != SCM_RIGHTS\n");
			return -1;
		}
		*recvfd = *((int *) CMSG_DATA(cmptr));
	}
	else {
		*recvfd = -1; /* descriptor was not passed */
	}
	return n;
}

