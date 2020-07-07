#ifndef SSA_DAEMON_STRUCTS_H
#define SSA_DAEMON_STRUCTS_H

#include <event2/util.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "hashmap.h"
#include "hashmap_str.h"

#define ID_NOT_SET 0 /* for connection and sock_context id */
#define MAX_ERR_STRING 128
#define MAX_HOSTNAME 255
#define MAX_CERTKEY_PAIRS 5
#define NO_FD -1 /** Designation for bufferevent with no set fd */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define NO_REVOCATION_CHECKS     (1 << 0)
#define NO_OCSP_STAPLED_CHECKS   (1 << 1)
#define NO_OCSP_RESPONDER_CHECKS (1 << 2)
#define NO_CRL_RESPONDER_CHECKS  (1 << 3)
#define NO_CACHED_CHECKS        (1 << 4)

#define turn_off_revocation_checks(checks) (checks |= NO_REVOCATION_CHECKS)
#define turn_on_revocation_checks(checks) (checks &= ~NO_REVOCATION_CHECKS)
#define has_revocation_checks(checks) !(checks & NO_REVOCATION_CHECKS)

#define turn_off_stapled_checks(checks) (checks |= NO_OCSP_STAPLED_CHECKS)
#define turn_on_stapled_checks(checks) (checks &= ~NO_OCSP_STAPLED_CHECKS)
#define has_stapled_checks(checks) !(checks & NO_OCSP_STAPLED_CHECKS)

#define turn_off_ocsp_checks(checks) (checks |= NO_OCSP_RESPONDER_CHECKS)
#define turn_on_ocsp_checks(checks) (checks &= ~NO_OCSP_RESPONDER_CHECKS)
#define has_ocsp_checks(checks) !(checks & NO_OCSP_RESPONDER_CHECKS)

#define turn_off_crl_checks(checks) (checks |= NO_CRL_RESPONDER_CHECKS)
#define turn_on_crl_checks(checks) (checks &= ~NO_CRL_RESPONDER_CHECKS)
#define has_crl_checks(checks) !(checks & NO_CRL_RESPONDER_CHECKS)

#define turn_off_cached_checks(checks) (checks |= NO_CACHED_CHECKS)
#define turn_on_cached_checks(checks) (checks &= ~NO_CACHED_CHECKS)
#define has_cached_checks(checks) !(checks & NO_CACHED_CHECKS)


struct daemon_ctx_st;
struct global_config_st;

struct revocation_ctx_st;
struct crl_responder_st;
struct ocsp_responder_st;

struct socket_ctx_st;
struct channel_st;


typedef struct global_config_st global_config;
typedef struct daemon_ctx_st daemon_ctx;

typedef struct revocation_ctx_st revocation_ctx;
typedef struct crl_responder_st crl_responder;
typedef struct ocsp_responder_st ocsp_responder;

typedef struct socket_ctx_st socket_ctx;
typedef struct channel_st channel;

enum socket_state {
	SOCKET_ERROR = 0,
    SOCKET_NEW,
    SOCKET_CONNECTING,
    SOCKET_FINISHING_CONN, /* revocation checks, connecting internally */
    SOCKET_CONNECTED,
    SOCKET_LISTENING,
    SOCKET_ACCEPTED,
    SOCKET_DISCONNECTED
};


enum tls_version {
    TLS_DEFAULT_ENUM = 0,
    TLS1_0_ENUM,
    TLS1_1_ENUM,
    TLS1_2_ENUM,
    TLS1_3_ENUM
};

enum revocation_state {
    REV_S_PENDING,
    REV_S_PASS,
    REV_S_FAIL
};


struct daemon_ctx_st {
	struct event_base* ev_base;
	struct evdns_base* dns_base;
	struct nl_sock* netlink_sock;
	int netlink_family;
	int port; /** Port to use for both listening and netlink */
	hmap_t* sock_map;
	hmap_t* sock_map_port;
    global_config* settings;

	hsmap_t* revocation_cache;
    hsmap_t* session_cache;
};

struct global_config_st {

    char* ca_path;

    /* WARNING: make sure each only contains one cipher (eg AES_GCM:NULL). */
    /* ANOTHER WARNING: also watch out for '\b' */
    char** cipher_list;
    int cipher_list_cnt;

    char** ciphersuites;
    int ciphersuite_cnt;

    int tls_compression;
    int session_tickets;
    int session_timeout;
    int max_chain_depth;
    int ct_checks;

    enum tls_version min_tls_version;
    enum tls_version max_tls_version;

    char* certificates[MAX_CERTKEY_PAIRS]; /* can be file or folder */
    int cert_cnt;

    char* private_keys[MAX_CERTKEY_PAIRS];
    int key_cnt;

    int revocation_checks;
};



typedef struct channel_st {
	struct bufferevent* bev;
	int closed;
} channel;



struct revocation_ctx_st {
    socket_ctx* sock_ctx;
    daemon_ctx *daemon;
    unsigned long id;

	unsigned int checks; // bitmap; see defined options above

    int *responders_at;
    int *crl_responders_at;
    int total_to_check;
    int left_to_check;

    ocsp_responder* ocsp_responders;
    crl_responder* crl_responders;

    X509_STORE* store;
    STACK_OF(X509)* certs;
};

struct ocsp_responder_st {

    revocation_ctx* rev_ctx;

    struct bufferevent* bev;
    char* url;

    int cert_position;

    OCSP_CERTID* certid;

    unsigned char* buffer;
    int buf_size;
    int tot_read;
    int is_reading_body;

    ocsp_responder* next;
};

struct crl_responder_st {

    struct bufferevent* bev;

    crl_responder* next;
};
 

struct socket_ctx_st {

	daemon_ctx* daemon;
	unsigned long id;

    enum socket_state state;

    SSL_CTX* ssl_ctx;
	SSL* ssl;
	evutil_socket_t sockfd;

	channel plain;
	channel secure;
	struct evconnlistener* listener;

	revocation_ctx rev_ctx;

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
    int accept_port;


	char rem_hostname[MAX_HOSTNAME+1];

    char err_string[MAX_ERR_STRING+1];
    unsigned int handshake_err_code;
};



daemon_ctx *daemon_context_new(char* config_path, int port);
void daemon_context_free(daemon_ctx* daemon);

int socket_context_new(socket_ctx** sock, int fd, 
            daemon_ctx* ctx, unsigned long id);
socket_ctx* accepting_socket_ctx_new(socket_ctx* listener_ctx, int fd);
void socket_shutdown(socket_ctx* sock_ctx);
void socket_context_free(socket_ctx* sock_ctx);
void socket_context_erase(socket_ctx* sock_ctx, int port);

int revocation_context_setup(revocation_ctx* ctx, socket_ctx* sock_ctx);
void revocation_context_cleanup(revocation_ctx* ctx);

void ocsp_responder_shutdown(ocsp_responder* resp);
void ocsp_responder_free(ocsp_responder* resp);

int check_socket_state(socket_ctx* sock_ctx, int num, ...);

int get_port(struct sockaddr* addr);





#endif