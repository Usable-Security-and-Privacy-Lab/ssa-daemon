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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netlink/genl/genl.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "daemon.h"
#include "daemon_structs.h"
#include "hashmap.h"
#include "in_tls.h"
#include "log.h"
#include "netlink.h"
#include "tls_client.h"
#include "tls_common.h"
#include "tls_server.h"


#define MAX_UPGRADE_SOCKET  18


/* SSA direct functions */
static void accept_error_cb(struct evconnlistener *listener, void *ctx);
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void signal_cb(evutil_socket_t fd, short event, void* arg);
static evutil_socket_t create_server_socket(ev_uint16_t port,
		int family, int protocol);

/* SSA listener functions */
static void listener_accept_error_cb(struct evconnlistener *listener, void *ctx);
static void listener_accept_cb(struct evconnlistener *listener,
		evutil_socket_t fd, struct sockaddr *address, int socklen, void *arg);

/* special */
static evutil_socket_t create_upgrade_socket(int port);
static void upgrade_recv(evutil_socket_t fd, short events, void *arg);
ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes,
		int *recvfd, struct sockaddr_un* addr, int addr_len);



/**
 * Performs all of the steps needed to run the SSA daemon, estabilshes
 * a netlink connection with the kernel module, begins listening on the given 
 * port for connections, and runs the libevent event base indefinitely.
 * This function only returns if an unrecoverable error occurred in the
 * Daemon, or if a SIGINT signal was sent to the process.
 * @param port The port to listen on for new connections.
 * @param config_path A NULL-terminated string identifying the file path
 * of a .yml configuration for the daemon.
 * @returns EXIT_SUCCESS (0) if the event base ran for some indeterminate
 * amount of time successfully, or EXIT_FAILURE (1) if an error occurred
 * before the event base could run.
 */
int run_daemon(int port, char* config_path) {

	struct evconnlistener* listener = NULL;
	daemon_context* daemon = NULL;

	evutil_socket_t upgrade_sock;
	evutil_socket_t server_sock;
	
	struct event* upgrade_ev = NULL;
	struct event* sev_pipe = NULL;
	struct event* sev_int = NULL;
	struct event* nl_ev = NULL;

	daemon = daemon_context_new(config_path, port);
	if (daemon == NULL)
		goto err;

	log_printf(LOG_INFO, 
			"Using libevent version %s with %s behind the scenes\n", 
			event_get_version(), event_base_get_method(daemon->ev_base));


	/* Signal handler registration */
	sev_pipe = evsignal_new(daemon->ev_base, SIGPIPE, signal_cb, NULL);
	if (sev_pipe == NULL)
		goto err;
	evsignal_add(sev_pipe, NULL);

	sev_int = evsignal_new(daemon->ev_base, SIGINT, signal_cb, daemon->ev_base);
	if (sev_int == NULL)
		goto err;
	evsignal_add(sev_int, NULL);


	/* Set up server socket with event base */
	server_sock = create_server_socket(port, PF_INET, SOCK_STREAM);
	listener = evconnlistener_new(daemon->ev_base, accept_cb, (void*) daemon,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	if (listener == NULL) 
		goto err;

	evconnlistener_set_error_cb(listener, accept_error_cb);

	nl_ev = event_new(daemon->ev_base, nl_socket_get_fd(daemon->netlink_sock),
			EV_READ | EV_PERSIST, netlink_recv, daemon->netlink_sock);
	if (nl_ev == NULL)
		goto err;

	/* lower priority than read/write ops--they're 1 */
	if (event_priority_set(nl_ev, 2) != 0)
		goto err;
	if (event_add(nl_ev, NULL) != 0)
		goto err;

	/* Set up upgrade notification socket with event base */
	upgrade_sock = create_upgrade_socket(port);
	upgrade_ev = event_new(daemon->ev_base, upgrade_sock,
			EV_READ | EV_PERSIST, upgrade_recv, daemon);
	if (event_add(upgrade_ev, NULL) == -1)
		goto err;



	/* Main event loop */
	if (event_base_dispatch(daemon->ev_base) != 0)
		goto err;



	log_printf(LOG_INFO, "Main event loop terminated\n");

	/* Cleanup */
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	libevent_global_shutdown();
#endif

	daemon_context_free(daemon);
	evconnlistener_free(listener); /* This also closes the socket */
	event_free(nl_ev);
	event_free(upgrade_ev);
	event_free(sev_pipe);
	event_free(sev_int);

	OPENSSL_cleanup();

    return EXIT_SUCCESS;
 err:

	printf("An error occurred setting up the daemon: %s\n", strerror(errno));

	if (daemon != NULL)
		daemon_context_free(daemon);
	if (listener != NULL)
		evconnlistener_free(listener); /* This also closes the socket */
	if (nl_ev != NULL)
		event_free(nl_ev);
	if (upgrade_ev != NULL)
		event_free(upgrade_ev);
	if (sev_pipe != NULL)
		event_free(sev_pipe);
	if (sev_int != NULL)
		event_free(sev_int);

	return EXIT_FAILURE;
}



evutil_socket_t create_upgrade_socket(int port) {

	evutil_socket_t sock;
	int ret;
	struct sockaddr_un addr;
	unsigned long addrlen;
	char name[MAX_UPGRADE_SOCKET];
	int namelen = snprintf(name, MAX_UPGRADE_SOCKET, "%ctls_upgrade%d", '\0', port);

	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, name, namelen);
	addrlen = namelen + sizeof(sa_family_t);

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

/**
 * Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent).
 * @param port The local port to listen on.
 * @param type SOCK_STREAM or SOCK_DGRAM.
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type) {
	evutil_socket_t sock;
	char port_buf[6];
	int ret;

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
	 */
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

/**
 * This function is called after an internal program calls connect() and after
 * that given TLS connection successfully finishes its handshake, but before
 * connect() returns for the internal program. That may seem confusing--here's
 * another way to think of it. Once the daemon has connected on the secure 
 * channel, it notifies the kernel module. The kernel module then takes the
 * `connect()` request from the internal program and reroutes it to this 
 * daemon's listening port and address (rather than the external one). This is 
 * the function that is called once that connection is successfully established.
 * @param listener The listener that the SSA Daemon uses to accept connections 
 * from internal programs.
 * @param fd The socket that is now connected with the internal program.
 * @param address The internal program's address/port combo, encapsulated 
 * within a sockaddr struct.
 * @param addrlen The length of address.
 * @param arg A void pointer referencing the daemon_context of the daemon.
 * 
 * WARNING: This is NOT the callback for a listening socket to receive
 * a new connection. The function for that is listener_accept_cb.
 */
void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
		struct sockaddr *address, int addrlen, void *arg) {
	daemon_context* daemon = (daemon_context*)arg;
	sock_context* sock_ctx;
	int port, ret;
	
	log_printf(LOG_INFO, "Received internal part of client connection\n");

	port = get_port(address);
	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Unauthorized connection on port %d\n", port);
		return; /* Should not notify the kernel */
	}

	if (sock_ctx->conn->state != CLIENT_CONNECTING) {
		log_printf(LOG_ERROR, "accept_cb() called on bad connection\n");
		goto err;
	}

	/* the odds of this are *pretty much nil* */
	if (evutil_make_socket_nonblocking(fd) == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		ret = -ECONNABORTED; /* could be EVUTIL_SOCKET_ERROR() maybe */
		goto err;
	}

	log_printf_addr(&sock_ctx->rem_addr);

	ret = associate_fd(sock_ctx->conn, fd);
	if (ret < 0)
		goto err;

	hashmap_del(daemon->sock_map_port, port);
	sock_ctx->conn->state = CLIENT_CONNECTED;

	return;
 err:
	if (sock_ctx != NULL) {
		hashmap_del(daemon->sock_map_port, port);
		connection_shutdown(sock_ctx);
		sock_ctx->conn->state = CONN_ERROR;
	}

	EVUTIL_CLOSESOCKET(fd);
	return;
}

/**
 * Callback function that is called whenever an accept() call fails on the
 * main connection listener. This function ignores several errno values; the
 * reason for this can be found in man accept(2), under RETURN VALUE.
 * Additionally, this function ignores ECONNABORTED. The reason can be found
 * here: https://bit.ly/3eHZzFZ
 * Lastly, it ignores EINTR as that error simply means that a signal
 * interrupted the system call before a connection came in.
 * @param listener The SSA daemon's main listener for client connections.
 * @param ctx A void pointer to the daemon_context.
 * @returns No return, but exits the event base loop if the error is fatal.
 */
void accept_error_cb(struct evconnlistener *listener, void *ctx) {

	struct event_base* base = NULL;
	int err = EVUTIL_SOCKET_ERROR();

	switch (err) {
	case ENETDOWN:
	case EPROTO:
	case ENOPROTOOPT:
	case EHOSTDOWN:
	case ENONET:
	case EHOSTUNREACH:
	case EOPNOTSUPP:
	case ENETUNREACH:
	case ECONNABORTED:
	case EINTR:
		/* all these errors can be ignored */
		log_printf(LOG_INFO, "Got a nonfatal error %d (%s) on the listener\n",
				err, evutil_socket_error_to_string(err));
		break;
	default:
		log_printf(LOG_ERROR, "Fatal error %d (%s) on the main listener\n",
				err, evutil_socket_error_to_string(err));
		base = evconnlistener_get_base(listener);
		event_base_loopexit(base, NULL);
	}
	return;
}

/**
 * When an external client connects to the server, this callback is called.
 * It is analagous to accept() in normal HTTP connections, but is intended
 * to do everything needed to begin a TLS connection with theexternal client.
 * If this function completes successfully, then tls_bev_events_cb will be
 * called once the TLS handshake has completed. If not, the connection to the
 * client will be dropped.
 * @param efd The file descriptor of the peer that has sent the connect()
 * request to our server. 'Peer' should not be confused with the programmer
 * interacting via c POSIX sockets calls to the daemon; it is simply someone
 * creating a connection with the socket to which this listener_accept_cb
 * was assigned with.
 * @param address The address information sent by the connecting client.
 * @param addrlen The length of the address info sent by the connecting client.
 */
void listener_accept_cb(struct evconnlistener *listener, evutil_socket_t efd,
	struct sockaddr *address, int addrlen, void *arg) {

	struct sockaddr_in int_addr = {
		.sin_family = AF_INET,
		.sin_port = 0, /* allow kernel to give us a random port */
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	sock_context* listening_sock_ctx = (sock_context*)arg;
	daemon_context* daemon = listening_sock_ctx->daemon;
	sock_context* accepting_sock_ctx = NULL;
	socklen_t intaddr_len = sizeof(int_addr);
	evutil_socket_t ifd = -1;
	int ret = 0, port;

	log_printf(LOG_INFO, "New connection incoming for server\n");

	ret = evutil_make_socket_nonblocking(efd);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Failed to set external socket non-blocking: %s\n",
				   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		goto err;
	}

	ret = sock_context_new(&accepting_sock_ctx, daemon, ID_NOT_SET);
	if (ret != 0)
		goto err;

	accepting_sock_ctx->fd = efd;
	/* NOTE: the id is TEMPORARY, to notify the kernel correctly upon a
	 * successful connection. MAKE SURE not to free the sock_ctx associated 
	 * with this id from the hashmap!! It's the id of the listener!! */
	accepting_sock_ctx->id = listening_sock_ctx->id;

	ret = connection_new(&(accepting_sock_ctx->conn));
	if (ret != 0)
		goto err;

	accepting_sock_ctx->conn->state = SERVER_CONNECTING;

	ret = accept_SSL_new(accepting_sock_ctx->conn, listening_sock_ctx->conn);
	if (ret != 0)
		goto err;

	ifd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ifd == -1) {
		log_printf(LOG_ERROR, "Failed to create a new socket: %s\n",
				   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		goto err;
	}

	ret = evutil_make_socket_nonblocking(ifd);
	if (ret != 0) {
		log_printf(LOG_ERROR, "Failed to set internal socket non-blocking: %s\n",
			 	   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		goto err;
	}

	if (bind(ifd, (struct sockaddr*)&int_addr, sizeof(int_addr)) == -1)
		goto err;

	/* refresh the sockaddr info to get the port the kernel assigned us */
	if (getsockname(ifd, (struct sockaddr*)&int_addr, &intaddr_len) == -1)
		goto err;

	ret = accept_connection_setup(accepting_sock_ctx, listening_sock_ctx, ifd);
	if (ret != 0)
		goto err;

	/* now convert the random port the kernel had assigned us */
	port = (int)ntohs((&int_addr)->sin_port);
	hashmap_add(daemon->sock_map_port, port, (void*)accepting_sock_ctx);
	return;
 err:
	log_printf(LOG_ERROR, "Failed to receive remote client connection: "
			"closing connection.\n");

	if (accepting_sock_ctx != NULL)
		sock_context_free(accepting_sock_ctx);

	if (ifd != -1)
		EVUTIL_CLOSESOCKET(ifd);

	return;
}

void listener_accept_error_cb(struct evconnlistener *listener, void *arg) {

	sock_context* sock_ctx = (sock_context*) arg;
	connection* conn = sock_ctx->conn;
	int err = EVUTIL_SOCKET_ERROR();

	switch (err) {
	case ENETDOWN:
	case EPROTO:
	case ENOPROTOOPT:
	case EHOSTDOWN:
	case ENONET:
	case EHOSTUNREACH:
	case EOPNOTSUPP:
	case ENETUNREACH:
	case ECONNABORTED:
	case EINTR:
		log_printf(LOG_INFO, "Recoverable error %d (%s) on a server listener\n",
				err, evutil_socket_error_to_string(err));
		/* all these errors can be ignored */
		break;
	default:
		log_printf(LOG_ERROR, "Fatal error %d (%s) on a server listener\n",
				err, evutil_socket_error_to_string(err));

		SSL_free(conn->tls);
		evconnlistener_free(listener);
		sock_ctx->fd = -1;
		conn->state = CONN_ERROR;

		set_err_string(conn, "External listener failed with error %i: %s",
				err, strerror(err));
		netlink_error_notify_kernel(sock_ctx->daemon, sock_ctx->id);
		break;
	}

	/* TODO: put netlink_notify_kernel out here? */
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

/**
 * The callback invoked when an internal program calls socket() with the
 * IPPROTO_TLS option. This function creates a socket within the daemon
 * that mirrors any settings or functionality set by the internal program.
 * That socket is added to a hashmap (sock_map), and is used to establish
 * encrypted connections with the external peer via TLS protocols.
 * @param daemon A pointer to the program's daemon_context.
 * @param id A uniquely generated ID for the given socket; corresponds with
 * (though is not equal to) the internal program's file descriptor of that
 * socket.
 * @param comm The address path of the calling program.
 * @returns (via netlink) a notification of 0 on success, or -errno on failure.
 */
void socket_cb(daemon_context* daemon, unsigned long id, char* comm) {

	sock_context* sock_ctx;
	evutil_socket_t fd = -1;
	int response = 0;

	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx != NULL) {
		log_printf(LOG_ERROR,
				"We have created a socket with this ID already: %lu\n", id);
		response = -EBADF;
		sock_ctx = NULL; /* err would try to free sock_ctx otherwise */
		goto err;
	}

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		response = -errno;
		goto err;
	}

	/* whether server or client, we need non blocking sockets for bufferevent */
	
	if (evutil_make_socket_nonblocking(fd) != 0) {
		response = -EVUTIL_SOCKET_ERROR();
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(-response));
		goto err;
	}
	
	response = sock_context_new(&sock_ctx, daemon, id);
	if (response != 0)
		goto err;

	response = connection_new(&(sock_ctx->conn));
	if (response != 0)
		goto err;

	response = client_SSL_new(sock_ctx->conn, daemon);
	if (response != 0)
		goto err;

	sock_ctx->fd = fd;
	sock_ctx->conn->state = CLIENT_NEW;

	hashmap_add(daemon->sock_map, id, (void*)sock_ctx);

	log_printf(LOG_INFO, "Socket created on behalf of application %s\n", comm);
	netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);
	return;
 err:
	if (fd != -1)
		close(fd);
	if (sock_ctx != NULL)
		sock_context_free(sock_ctx);

	log_printf(LOG_ERROR, "Socket failed to be created: %i\n", response);

	netlink_notify_kernel(daemon, id, response);
	return;
}

void setsockopt_cb(daemon_context* ctx, unsigned long id, int level,
		int option, void* value, socklen_t len) {

	sock_context* sock_ctx;
	connection* conn;
	int response = 0; /* Default is success */

	sock_ctx = (sock_context*)hashmap_get(ctx->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(ctx, id, -EBADF);
		return;
	}

	conn = sock_ctx->conn;
	clear_err_string(conn);

	switch (option) {
	case TLS_REMOTE_HOSTNAME:
		if ((response = check_conn_state(conn, 1, CLIENT_NEW)) != 0)
			break;

		memcpy(sock_ctx->rem_hostname, value, len); /* kernel validated this */
		log_printf(LOG_INFO,
				"Assigning %s to socket %lu\n", sock_ctx->rem_hostname, id);

		response = set_remote_hostname(sock_ctx->conn, value);
		break;

	case TLS_DISABLE_CIPHER:
		if ((response = check_conn_state(conn, 2, CLIENT_NEW, SERVER_NEW)) != 0)
			break;
		response = disable_cipher(sock_ctx->conn, (char*) value);
		break;

	case TLS_TRUSTED_PEER_CERTIFICATES:
		if ((response = check_conn_state(conn, 2, CLIENT_NEW, SERVER_NEW)) != 0)
			break;
		response = set_trusted_CA_certificates(sock_ctx->conn, (char*) value);
		break;

	case TLS_CLIENT_CONNECTION:
		if ((response = check_conn_state(conn, 1, SERVER_NEW)) != 0)
			break;
		response = set_connection_client(sock_ctx->conn, ctx);
		break;

	case TLS_SERVER_CONNECTION:
		if ((response = check_conn_state(conn, 1, CLIENT_NEW)) != 0)
			break;
		response = set_connection_server(sock_ctx->conn, ctx);
		break;

	case TLS_CERTIFICATE_CHAIN:
		if ((response = check_conn_state(conn, 1, SERVER_NEW)) != 0)
			break;
		response = set_certificate_chain(sock_ctx->conn, (char*) value);
		break;

	case TLS_PRIVATE_KEY:
		if ((response = check_conn_state(conn, 1, SERVER_NEW)) != 0)
			break;
		response = set_private_key(sock_ctx->conn, value);
		break;

	case TLS_ERROR:
	case TLS_HOSTNAME:
	case TLS_TRUSTED_CIPHERS:
	case TLS_ID:
		response = -ENOPROTOOPT; /* all get only */
		break;
	default:
		if (setsockopt(sock_ctx->fd, level, option, value, len) == -1) {
			response = -errno;
			set_err_string(conn, "Daemon error: internal fd setsockopt failed");
		}
		break;
	}

	netlink_notify_kernel(ctx, id, response);
	return;
}

void getsockopt_cb(daemon_context* daemon, 
		unsigned long id, int level, int option) {

	sock_context* sock_ctx;
	connection* conn;
	/* long value; */
	int response = 0;
	char* data = NULL;
	unsigned int len = 0;
	int need_free = 0;

	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		netlink_notify_kernel(daemon, id, -EBADF);
		return;
	}
	conn = sock_ctx->conn;

	switch (option) {
	case TLS_ERROR:
		//Can be checked in any connection state
		if (!has_err_string(conn)) {
			response = -EINVAL;
			break;
		}

		data = sock_ctx->conn->err_string;
		len = strlen(conn->err_string) + 1;
		break;

	case TLS_REMOTE_HOSTNAME:
		if ((response = check_conn_state(conn,
				2, CLIENT_NEW, CLIENT_CONNECTED)) != 0)
			break;

		if (strlen(sock_ctx->rem_hostname) > 0) {
			data = sock_ctx->rem_hostname;
			len = strlen(sock_ctx->rem_hostname) + 1;
		}
		break;

	case TLS_HOSTNAME:
		if ((response = check_conn_state(conn, 
				3, SERVER_NEW, SERVER_LISTENING, SERVER_CONNECTED)) != 0)
			break;

		if(get_hostname(conn, &data, &len) == 0) {
			response = -EINVAL;
		}
		break;

	case TLS_PEER_IDENTITY:
		if ((response = check_conn_state(conn, 2, 
				CLIENT_CONNECTED, SERVER_CONNECTED)) != 0)
			break;

		response = get_peer_identity(conn, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_PEER_CERTIFICATE_CHAIN:
		if ((response = check_conn_state(conn, 1, CLIENT_CONNECTED)) != 0)
			break;
		response = get_peer_certificate(conn, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_TRUSTED_CIPHERS:
		if ((response = check_conn_state(conn, 5, CLIENT_NEW, SERVER_NEW, 
				CLIENT_CONNECTED, SERVER_CONNECTED, SERVER_LISTENING)) != 0)
			break;
		response = get_enabled_ciphers(conn, &data, &len);
		if (response == 0)
			need_free = 1;
		break;

	case TLS_TRUSTED_PEER_CERTIFICATES:
	case TLS_PRIVATE_KEY:
	case TLS_DISABLE_CIPHER:
	case TLS_REQUEST_PEER_AUTH:
		response = -ENOPROTOOPT; /* all set only */
		clear_err_string(conn);
		break;

	case TLS_ID:
		/* This case is handled directly by the kernel.
		 * If we want to change that, uncomment the lines below */
		/* data = &id;
		len = sizeof(id);
		break; */
	default:
		log_printf(LOG_ERROR,
				"Default case for getsockopt hit: should never happen\n");
		response = -EBADF;
		clear_err_string(conn);
		break;
	}
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	clear_err_string(conn);

	netlink_send_and_notify_kernel(daemon, id, data, len);
	if (need_free == 1)
		free(data);
	
	return;
}

void bind_cb(daemon_context* daemon, unsigned long id,
			 struct sockaddr* int_addr, int int_addrlen,
			 struct sockaddr* ext_addr, int ext_addrlen) {

	sock_context* sock_ctx = NULL;
	connection* conn;
	int response = 0;

	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		goto err;
	}

	conn = sock_ctx->conn;

	response = check_conn_state(conn, 2, CLIENT_NEW, SERVER_NEW);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	if (evutil_make_listen_socket_reuseable(sock_ctx->fd) != 0) {
		log_printf(LOG_ERROR,
				"Failed in evutil_make_listen_socket_reusable: %s\n",
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		response = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Bind error: "
				"SSA daemon's internal socket couldn't be made reusable");
		goto err;
	}

	if (bind(sock_ctx->fd, ext_addr, ext_addrlen) != 0) {
		response = -errno;
		set_err_string(conn, "Bind error: SSA daemon socket failed to bind");
		goto err;
	}

	sock_ctx->int_addr = *int_addr;
	sock_ctx->int_addrlen = int_addrlen;
	sock_ctx->ext_addr = *ext_addr;
	sock_ctx->ext_addrlen = ext_addrlen;

	netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);
	clear_err_string(conn);
	return;
 err:

	if (sock_ctx != NULL) {
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
		sock_ctx->fd = -1;
		SSL_free(sock_ctx->conn->tls);
		sock_ctx->conn->tls = NULL;

		sock_ctx->conn->state = CONN_ERROR;
	}

	netlink_notify_kernel(daemon, id, response);
	return;
}

/**
 * Begins an attempt to connect via TLS to the remote host. Upon completion,
 * the function client_bev_event_cb() will be called with the appropriate events
 * (BEV_EVENT_CONNECTED on success, BEV_EVENT_ERROR on failure). Since the
 * daemon's internal sockets are always set to non-blocking, this function
 * does not notify the kernel (unless a failure happened from within the
 * function); that is left up to the callback function.
 * @param daemon_ctx The daemon context associated with this daemon.
 * @param id The ID of the socket to attempt to connect. This is used along
 * with a hashmap (sock_map) found in the daemon context in order to retrieve
 * the context specific to the socket being called by the user.
 * @param int_addr The address of the internal peer calling these functions.
 * @param int_addrlen The length of int_addr.
 * @param ext_addr The address of the server we're attempting to connect to.
 * @param ext_addrlen The length of ext_addr.
 * @param blocking Set as 1 if the user's socket is blocking, or 0
 * if it is set as non-blocking. If it is non-blocking, then this function
 * will notify the kernel with the EINPROGRESS errno code before returning.
 * @return No return value--meant to send a netlink message if something is
 * to be returned.
 */
void connect_cb(daemon_context* daemon, unsigned long id,
		struct sockaddr* int_addr, int int_addrlen,
		struct sockaddr* rem_addr, int rem_addrlen, int blocking) {

	sock_context* sock_ctx;
	connection* conn;
	int response = 0, port, ret;

	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		goto err;
	}

	conn = sock_ctx->conn;

	clear_err_string(conn);

	response = check_conn_state(conn, 
			3, CLIENT_NEW, CLIENT_CONNECTING, CLIENT_CONNECTED);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}

	if (conn->state == CLIENT_CONNECTING) {
		netlink_notify_kernel(daemon, id, -EALREADY);
		return;
	} else if (conn->state == CLIENT_CONNECTED) {
		netlink_notify_kernel(daemon, id, -EISCONN);
		return;
	}

	// state == CLIENT_NEW - we need to initiate the connection

	sock_ctx->int_addr = *int_addr;
	sock_ctx->int_addrlen = int_addrlen;
	sock_ctx->rem_addr = *rem_addr;
	sock_ctx->rem_addrlen = rem_addrlen;

	response = client_connection_setup(sock_ctx);
	if (response != 0)
		goto err;

	ret = bufferevent_socket_connect(conn->secure.bev, rem_addr, rem_addrlen);
	if (ret != 0) {
		response = -EVUTIL_SOCKET_ERROR();
		set_err_string(conn, "Connection setup error: "
				"Failed to initiate TLS handshake with external endpoint");
		goto err;
	}

	port = get_port(int_addr);
	log_printf(LOG_INFO, "Placing sock_ctx for port %d\n", port);

	hashmap_add(daemon->sock_map_port, port, sock_ctx);
	conn->state = CLIENT_CONNECTING;

	if (!blocking) {
		log_printf(LOG_INFO, "Nonblocking connect requested\n");
		netlink_notify_kernel(daemon, id, -EINPROGRESS);
	}

	return;
 err:
	
	if (sock_ctx != NULL) {
		connection_shutdown(sock_ctx);
		conn->state = CONN_ERROR;
	}

	netlink_notify_kernel(daemon, id, response);
	return;
}

void listen_cb(daemon_context* daemon, unsigned long id,
			   struct sockaddr* int_addr, int int_addrlen,
			   struct sockaddr* ext_addr, int ext_addrlen) {

	sock_context* sock_ctx = NULL;
	connection* conn;
	int response = 0;

	sock_ctx = (sock_context*)hashmap_get(daemon->sock_map, id);
	if (sock_ctx == NULL) {
		response = -EBADF;
		goto err;
	}

	conn = sock_ctx->conn;
	clear_err_string(conn);

	/* convert a CLIENT_NEW connection into a SERVER_NEW automatically */
	if (conn->state == CLIENT_NEW) {
		response = server_SSL_new(conn, daemon);
		if (response != 0) {
			set_err_string(conn, "Listener setup error: "
					"SSA daemon buffer allocation failed");
			goto err;
		}
		conn->state = SERVER_NEW;
	}

	response = check_conn_state(conn, 1, SERVER_NEW);
	if (response != 0) {
		netlink_notify_kernel(daemon, id, response);
		return;
	}


	/* set external-facing socket to listen */
	if (listen(sock_ctx->fd, SOMAXCONN) == -1) {
		response = -errno;
		set_err_string(conn, "Listener setup error: "
				"SSA daemon's external socket returned error on `listen()`");
		goto err;
	}

	sock_ctx->listener = evconnlistener_new(daemon->ev_base,
			listener_accept_cb, (void*) sock_ctx,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->fd);
	if (sock_ctx->listener == NULL) {
		response = -errno;
		set_err_string(conn, "Listener setup error: "
				"failed to allocate buffers within the SSA daemon");
		goto err;
	}
	evconnlistener_set_error_cb(sock_ctx->listener, listener_accept_error_cb);

	conn->state = SERVER_LISTENING;

	netlink_notify_kernel(daemon, id, NOTIFY_SUCCESS);

	log_printf(LOG_DEBUG, "port now listening for incoming connections\n");
	return;
 err:
	log_printf(LOG_ERROR, "listen_cb failed: %i.\n", response);
	netlink_notify_kernel(daemon, id, response);

	/* listener is the last failable thing set; no need to check it */
	SSL_free(sock_ctx->conn->tls);
	EVUTIL_CLOSESOCKET(sock_ctx->fd);

	sock_ctx->conn->state = CONN_ERROR;
	return;
}

/**
 * Finishes the process of accepting an incoming client connection.
 * This function is only called after the internal user calls accept()
 * and a TLS connection has been successfully made between the incoming
 * client and the daemon's internal socket. The purpose of this function
 * is to associate an id with the sock_ctx of the already accepted connection
 * so that the internal user can begin to communicate via the daemon to the
 * client.
 */
void associate_cb(daemon_context* daemon, unsigned long id,
		struct sockaddr* int_addr, int int_addrlen) {

	sock_context* sock_ctx;
	int port = get_port(int_addr);

	sock_ctx = hashmap_get(daemon->sock_map_port, port);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Port provided in associate_cb not found\n");
		netlink_notify_kernel(daemon, id, -EBADF);
		return;
	}

	if (sock_ctx->conn->state != SERVER_CONNECTING) {
		// Tear down this connection--nobody has access to it anyways */
		netlink_notify_kernel(daemon, id, -ECONNABORTED);
		connection_shutdown(sock_ctx);
		hashmap_del(daemon->sock_map_port, port);
		sock_context_free(sock_ctx);
		return;
	}

	hashmap_del(daemon->sock_map_port, port);

	sock_ctx->id = id;
	sock_ctx->conn->state = SERVER_CONNECTED;

	hashmap_add(daemon->sock_map, id, (void*)sock_ctx);

	netlink_notify_kernel(daemon, id, 0);
	return;
}

/**
 * Closes and frees all internal file descriptors and buffers associated
 * with a socket.
 * @param id The id of the socket to be closed.
 */
void close_cb(daemon_context* daemon_ctx, unsigned long id) {
	sock_context* sock_ctx;

	sock_ctx = (sock_context*)hashmap_get(daemon_ctx->sock_map, id);
	if (sock_ctx == NULL) {
		log_printf(LOG_ERROR, "Close called on non-existent socket\n");
		return;
	}

	switch (sock_ctx->conn->state) {
	case CLIENT_CONNECTING:
	case SERVER_CONNECTING:
	case CLIENT_CONNECTED:
	case SERVER_CONNECTED:
		connection_shutdown(sock_ctx);
		break;
	default:
		break;
	}

	sock_context_free(sock_ctx);
	hashmap_del(daemon_ctx->sock_map, id);
	return;
}

void upgrade_cb(daemon_context* daemon_ctx, unsigned long id,
		struct sockaddr* int_addr, int int_addrlen) {
	/* This was implemented in the kernel directly. */
	return;
}

void upgrade_recv(evutil_socket_t fd, short events, void *arg) {
	sock_context* sock_ctx;
	daemon_context* daemon_ctx = (daemon_context*)arg;
	char msg_buffer[256];
	int new_fd;
	int bytes_read;
	unsigned long id;
	int is_accepting;
	struct sockaddr_un addr = {};
	/* Why the 5? Because that's what linux uses for autobinds */
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
	log_printf(LOG_INFO, "Got a new %s descriptor %d,"
			" to be associated with %lu from addr %s\n",
			is_accepting == 1 ? "accepting" : "connecting",
			new_fd, id, addr.sun_path+1, addr_len);
	sock_ctx = (sock_context*)hashmap_get(daemon_ctx->sock_map, id);
	if (sock_ctx == NULL) {
		return;
	}
	EVUTIL_CLOSESOCKET(sock_ctx->fd);
	sock_ctx->fd = new_fd;
	/* set_connected(sock_ctx->state); */

	if (is_accepting == 1) {
		/* TODO: Eventually clean up this whole section--ripped from tls_opts_server_setup()... */
		SSL_CTX* server_settings = daemon_ctx->server_ctx;
		SSL_CTX_set_options(server_settings, SSL_OP_ALL);
		/* There's a billion options we can/should set here by admin config XXX
		* See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */

		/* XXX We can do all sorts of caching modes and define our own callbacks
		* if desired */
		SSL_CTX_set_session_cache_mode(server_settings, SSL_SESS_CACHE_SERVER);
		SSL_CTX_use_certificate_chain_file(server_settings, "test_files/localhost_cert.pem");
		SSL_CTX_use_PrivateKey_file(server_settings, "test_files/localhost_key.pem", SSL_FILETYPE_PEM);
		/* Thus concludes the TODO. */

		/* set_accepting(sock_ctx->state); */
	}
	else {
		/* used to have tls_opts_client_setup(sock_ctx->tls_opts); */
		/*set_not_accepting(sock_ctx->state);*/
	}

	if (sendto(fd, "GOT IT", sizeof("GOT IT"), 0, (struct sockaddr*)&addr, addr_len) == -1) {
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
		// message length of error or 0
		*recvfd = -1;
		return n;
	}

	if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
	    cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET) {
			log_printf(LOG_ERROR, "control level != SOL_SOCKET\n");
			*recvfd = -1;
			return -1;
		}
		if (cmptr->cmsg_type != SCM_RIGHTS) {
			log_printf(LOG_ERROR, "control type != SCM_RIGHTS\n");
			*recvfd = -1;
			return -1;
		}
		*recvfd = *((int *) CMSG_DATA(cmptr));
	}
	else {
		*recvfd = -1; /* descriptor was not passed */
	}
	return n;
}