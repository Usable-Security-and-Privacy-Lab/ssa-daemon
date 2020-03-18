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
	int port; /** Port to use for both listening and netlink */
	hmap_t* sock_map;
	hmap_t* sock_map_port;
	SSL_CTX* client_settings;
	SSL_CTX* server_settings; /* Modifying settings problems solved with SSL_dup() */
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

	struct sockaddr int_addr; /** Internal address/port--the program using SSA */
	int int_addrlen;
	union {
		struct sockaddr ext_addr;
		struct sockaddr rem_addr; /* The address we're trying to connect to */
	};
	union {
		int ext_addrlen;
		int rem_addrlen;
	};

	struct evconnlistener* listener;
	char rem_hostname[MAX_HOSTNAME];
	connection* tls_conn;
	int state; /** Different states are set independantly of each other */
	daemon_context* daemon;
} sock_context;



/* Bitmap constants for Connection->state */
#define CONN_SERVER 		0x01 /* 1 for Server, 0 for Client. All of these set to 0 by default */
#define CONN_BOUND 		0x02 /* Nonzero if we've called bind locally */
#define CONN_CONNECTED 		0x04
#define CONN_ACCEPTING 		0x08
#define CONN_CUSTOM_VALIDATION 	0x10

/* Macro getters/setters to simplify state bitmap access */
#define is_server(state) ((state) & CONN_SERVER) /** If it's not a server... it's a client. */
#define is_bound(state) ((state) & CONN_BOUND)
#define is_connected(state) ((state) & CONN_CONNECTED)
#define is_accepting(state) ((state) & CONN_ACCEPTING)
#define is_custom_validation(state) ((state) & CONN_CUSTOM_VALIDATION)

#define set_server(state) (state |= CONN_SERVER)
#define set_bound(state) (state |= CONN_BOUND)
#define set_connected(state) (state |= CONN_CONNECTED)
#define set_accepting(state) (state |= CONN_ACCEPTING)
#define set_custom_validation(state) (state |= CONN_CUSTOM_VALIDATION)

#define set_client(state) (state &= ~CONN_SERVER)
#define set_unbound(state) (state &= ~CONN_BOUND)
#define set_unconnected(state) (state &= ~CONN_CONNECTED)
#define set_not_accepting(state) (state &= ~CONN_ACCEPTING)
#define set_not_custom_validation(state) (state &= ~CONN_CUSTOM_VALIDATION)


#endif