#ifndef TLS_STRUCTS_H
#define TLS_STRUCTS_H

#define MAX_HOSTNAME 255


#include <netinet/in.h>

#include <event2/event.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "hashmap.h"
#include "queue.h"

typedef struct channel_st {
	struct bufferevent* bev;
	int closed;
	int connected;
} channel;

typedef struct daemon_context_st {
	struct event_base* ev_base;
	struct nl_sock* netlink_sock;
	int netlink_family;
	int port; /* Port to use for both listening and netlink */
	hmap_t* sock_map;
	hmap_t* sock_map_port;
	SSL_CTX* client_settings;
	SSL_CTX* server_settings;
} daemon_context;

typedef struct connection_st {
	channel plain;
	channel secure;
	SSL* tls;
	unsigned long id;
	daemon_context* daemon;
	struct sockaddr* addr;
	int addrlen;
} connection;

typedef struct sock_context_st {
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
	int is_connected; /* TODO: Add is_server and custom_validation options */
	int is_accepting; /* acting as a TLS server or client? */
	struct evconnlistener* listener;
	char rem_hostname[MAX_HOSTNAME];
	connection* tls_conn;
	daemon_context* daemon;
} sock_context;


#endif