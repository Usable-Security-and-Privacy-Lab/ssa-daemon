#ifndef DAEMON_STRUCTS_H
#define DAEMON_STRUCTS_H

#include <event2/util.h>

#include <openssl/ssl.h>

#include "hashmap.h"

#define ID_NOT_SET 0 /* for connection and sock_context id */
#define MAX_ERR_STRING 128
#define MAX_HOSTNAME 255
#define NOT_CONN_BEV -1 /** Designation for bufferevent with no set fd */

#define NO_REVOCATION_CHECKS     (1 << 0)
#define NO_OCSP_STAPLED_CHECKS   (1 << 1)
#define NO_OCSP_RESPONDER_CHECKS (1 << 2)
#define NO_CRL_RESPONDER_CHECKS  (1 << 3)


enum connection_state {
	CONN_ERROR = 0,
	CLIENT_NEW,
	CLIENT_CONNECTING,
	CLIENT_CONNECTED,
	SERVER_NEW,
	SERVER_LISTENING,
	SERVER_CONNECTING,
	SERVER_CONNECTED,
	DISCONNECTED
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
	SSL_CTX* client_ctx;
	SSL_CTX* server_ctx;

	hmap_t* rev_status_map;
} daemon_context;

typedef struct rev_client_st {
	struct bufferevent* bev;
	char* url;

	unsigned char* buffer; /**< A temporary buffer to store read data */
	int buf_size;
	int tot_read;
	int buffer_is_body;
} rev_client;

typedef struct revocation_context_st {
	unsigned int num_rev_checks; /**< How many different types of revocation will be checked */
	int crl_clients_left;

	rev_client* ocsp_clients;
	unsigned int ocsp_client_cnt;
	rev_client* crl_clients;
	unsigned int crl_client_cnt;

	int checks; // bitmap; see defined options above
} revocation_context; 

typedef struct connection_st {
	channel plain;
	channel secure;
	SSL* tls;
	struct sockaddr* addr; /* TODO: Used only for server-side connections?? */
	int addrlen;
	enum connection_state state;
	char* err_string;
} connection;

typedef struct sock_context_st {
	unsigned long id;
	evutil_socket_t fd;
	connection* conn;
	revocation_context revocation;

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
	char rem_hostname[MAX_HOSTNAME]; /* TODO: dynamically allocate */
	daemon_context* daemon;
} sock_context;


daemon_context *daemon_context_new(char* config_path, int port);
void daemon_context_free(daemon_context* daemon);

int sock_context_new(sock_context** sock, daemon_context* ctx, unsigned long id);
void sock_context_free(sock_context* sock_ctx);

void revocation_context_cleanup(revocation_context* ctx);
void responder_cleanup(rev_client resp);

int connection_new(connection** conn);
void connection_shutdown(sock_context* sock_ctx);
void connection_free(connection* conn);

int check_conn_state(connection* conn, int num, ...);

int has_err_string(connection* conn);
void set_err_string(connection* conn, char* string, ...);
void set_verification_err_string(connection* conn, unsigned long ssl_err);
void set_badfd_err_string(connection* conn);
void set_wrong_state_err_string(connection* conn);
void clear_err_string(connection* conn);

int ssl_malloc_err(connection* conn);

int associate_fd(connection* conn, evutil_socket_t ifd);
int get_port(struct sockaddr* addr);





#endif