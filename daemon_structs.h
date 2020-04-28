#ifndef DAEMON_STRUCTS_H
#define DAEMON_STRUCTS_H

#include <event2/util.h>

#include <openssl/ssl.h>

#include "hashmap.h"

#define ID_NOT_SET 0 /* for connection and sock_context id */
#define MAX_HOSTNAME 255
#define NOT_CONN_BEV -1 /** Designation for bufferevent with no set fd */

enum connection_state {
	CONN_ERROR,
	CLIENT_NEW,
	CLIENT_CONNECTING,
	CLIENT_CONNECTED,
	SERVER_NEW,
	SERVER_LISTENING,
	SERVER_CONNECTING,
	SERVER_CONNECTED,
	DISCONNECTED,
};



typedef struct channel_st {
	struct bufferevent* bev;
	int closed;
} channel;

typedef struct daemon_context_st {
	struct event_base* ev_base;
	struct nl_sock* netlink_sock;
	int netlink_family;
	int port; /** Port to use for both listening and netlink */
	hmap_t* sock_map;
	hmap_t* sock_map_port;
	SSL_CTX* client_settings;
	SSL_CTX* server_settings;
} daemon_context;

typedef struct connection_st {
	channel plain;
	channel secure;
	SSL* tls;
	struct sockaddr* addr; /* TODO: Used only for server-side connections?? */
	int addrlen;
	enum connection_state state;
} connection;

typedef struct sock_context_st {
	unsigned long id;
	evutil_socket_t fd;
	connection* conn;

	struct sockaddr int_addr; /** Internal address--the program using SSA */
	int int_addrlen;
	union {
		struct sockaddr ext_addr;
		struct sockaddr rem_addr;
	};
	union {
		int ext_addrlen;
		int rem_addrlen;
	};

	struct evconnlistener* listener;
	char rem_hostname[MAX_HOSTNAME];

	int error_code;
	daemon_context* daemon;
} sock_context;



int sock_context_new(sock_context** sock, daemon_context* ctx, unsigned long id);
void sock_context_free(sock_context* sock_ctx);

int connection_new(connection** conn);
void connection_shutdown(sock_context* sock_ctx);
void connection_free(connection* conn);

int associate_fd(connection* conn, evutil_socket_t ifd);



#endif