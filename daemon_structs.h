#ifndef SSA_DAEMON_STRUCTS_H
#define SSA_DAEMON_STRUCTS_H



#include <event2/util.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "hashmap.h"
#include "hashmap_str.h"


/** The maximum length that an error string may be (not including '\0') */
#define MAX_ERR_STRING 128

/** The maximum length that a hostname may be (not including '\0') */
#define MAX_HOSTNAME 255
#define MAX_CERTS 5
#define NO_FD -1 /** Designation for bufferevent with no set fd */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/** Flag to disable any revocation checks from being performed */
#define NO_REVOCATION_CHECKS     (1 << 0)
/** Flag to disable the OCSP stapled response from being used */
#define NO_OCSP_STAPLED_CHECKS   (1 << 1)
/** Flag to disable OCSP checks from being launched (not including stapled) */
#define NO_OCSP_RESPONDER_CHECKS (1 << 2)
/** Flag to disagle CRL checks from being launched */
#define NO_CRL_RESPONDER_CHECKS  (1 << 3)
/** Flag to disable cached responses from being used */
#define NO_CACHED_CHECKS         (1 << 4)


/**
 * Disables any revocation checks from being performed, and passes all TLS
 * handshakes (even if a revoked certificate is in use)
 */
#define turn_off_revocation_checks(checks) (checks |= NO_REVOCATION_CHECKS)

/**
 * Sets the connection so that the certificate chain must be fully checked for
 * any revoked certificates. If some certificates are unable to be checked,
 * this will mean that the connection will fail
 */
#define turn_on_revocation_checks(checks) (checks &= ~NO_REVOCATION_CHECKS)

/** Checks to determine whether revocation checks are required & enabled. */
#define has_revocation_checks(checks) !(checks & NO_REVOCATION_CHECKS)



/** Disables OCSP stapled responses from being used when checking revocation. */
#define turn_off_stapled_checks(checks) (checks |= NO_OCSP_STAPLED_CHECKS)

/** Allows OCSP stapled responses to be used as part of revocation checks. */
#define turn_on_stapled_checks(checks) (checks &= ~NO_OCSP_STAPLED_CHECKS)

/** Determines whether OCSP stapled response checks are enabled or not. */
#define has_stapled_checks(checks) !(checks & NO_OCSP_STAPLED_CHECKS)



/** Disables OCSP responders from being queried when checking revocation. */
#define turn_off_ocsp_checks(checks) (checks |= NO_OCSP_RESPONDER_CHECKS)

/** Allows OCSP responders to be queried when checking revocation. */
#define turn_on_ocsp_checks(checks) (checks &= ~NO_OCSP_RESPONDER_CHECKS)

/** Determines whether OCSP responders are enabled or not. */
#define has_ocsp_checks(checks) !(checks & NO_OCSP_RESPONDER_CHECKS)



/** Disables CRL responders from being queried when checking revocation. */
#define turn_off_crl_checks(checks) (checks |= NO_CRL_RESPONDER_CHECKS)

/** Allows CRL responders to be queried when checking revocation. */
#define turn_on_crl_checks(checks) (checks &= ~NO_CRL_RESPONDER_CHECKS)

/** Determines whether CRL responders are enabled or not. */
#define has_crl_checks(checks) !(checks & NO_CRL_RESPONDER_CHECKS)



/**
 * Disables cached responses from being used when checking revocation.
 * Note that this does not disable the daemon from actively caching responses.
 */
#define turn_off_cached_checks(checks) (checks |= NO_CACHED_CHECKS)

/** Allows cached responses to be used when checkin revocation. */
#define turn_on_cached_checks(checks) (checks &= ~NO_CACHED_CHECKS)

/** Determines whether cached responses are checked or not. */
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
    SOCKET_ERROR = 0,      /** Socket unrecoverably failed operation */
    SOCKET_NEW,            /** Fresh socket ready for `connect` or `listen` */
    SOCKET_CONNECTING,     /** Performing TCP or TLS handshake */
    SOCKET_FINISHING_CONN, /** revocation checks/connecting internally */
    SOCKET_CONNECTED,      /** Both endpoints connected (client) */
    SOCKET_LISTENING,      /** Socket listening/accepting connections */
    SOCKET_DISCONNECTED    /** Both endpoints closed cleanly (client/server) */
};


enum tls_version {
    TLS_DEFAULT_ENUM = 0, /** Default TLS version selected (TLS 1.3) */
    TLS1_0_ENUM,          /** TLS 1.0 version selected */
    TLS1_1_ENUM,          /** TLS 1.1 version selected */
    TLS1_2_ENUM,          /** TLS 1.2 version selected */
    TLS1_3_ENUM           /** TLS 1.3 version selected */
};


struct daemon_ctx_st {
    struct event_base* ev_base;   /** Multiplexer that handles all events */
    struct evdns_base* dns_base;  /** Handles all DNS lookups */
    struct nl_sock* netlink_sock; /** For transmitting to/from kernel module */
    int netlink_family;           /** Netlink protocol; should be SSA family */
    int port;                     /** Port for incoming connections/Netlink */
    hmap_t* sock_map;             /** Hashmap for pending server connections */
    hmap_t* sock_map_port;        /** Hashmap for sockets currently in use */
    global_config* settings;      /** Settings loaded in from config file */

    hsmap_t* revocation_cache;    /** Stores OCSP cert revocation statuses */
    /*
    hsmap_t* ssl_ctx_cache;
    */
};

struct global_config_st {

    char* ca_path;

    /* WARNING: make sure each only contains one cipher (eg AES_GCM:NULL). */
    /* ANOTHER WARNING: also watch out for '\b' */
    char** cipher_list;  /** List of acceptable TLS 1.2 ciphers to use */
    int cipher_list_cnt; /** Length of \p cipher_list */

    char** ciphersuites; /** List of acceptable TLS 1.3 ciphers to use */
    int ciphersuite_cnt; /** Length of \p ciphersuites */

    int session_tickets; /** 1 if session tickets enabled, 0 otherwise */
    int session_timeout; /** Length of time before session will expire */
    int max_chain_depth; /** Number of certificates acceptable in cert chain */
    int ct_checks;       /** 1 if Certificate Transparency enabled, 0 if not */

    enum tls_version min_tls_version; /** minimum accepted TLS version */
    enum tls_version max_tls_version; /** maximum accepted TLS version */

    char* certificates[MAX_CERTS]; /** list of files/folders of certs to use */
    int cert_cnt;                  /** Size of \p certificates list */

    char* private_keys[MAX_CERTS]; /** list of files/folders of keys to use */
    int key_cnt;                   /** Size of \p private_keys list */

    unsigned int revocation_checks; /** bitset of revocation settings */
    int session_resumption; /** 1 if sockets will reuse sessions, 0 if not */
};



typedef struct channel_st {
    struct bufferevent* bev; /** The bufferevent of a given endpoint */
    int closed;              /** 1 if the endpoint is done communicating */
} channel;



/**
 * Contains data directly related to performing revocation checks.
 * This struct is only really used if revocation checks are turned on.
 */
struct revocation_ctx_st {
    daemon_ctx *daemon;   /** The daemon's context */
    socket_ctx* sock_ctx; /** The parent socket_ctx of the rev context */
    unsigned long id;     /** The ID of the parent socket_ctx */

    unsigned int checks; /** bitmap of rev checks; options #define'd above */

    /** The number of active, authoritative responders performing revocation
     * checks for the certificate at the corresponding index in the cert chain.
     * For example, responders_at[0] would represent the number of responders
     * checking the leaf certificate of a chain, responders_at[1] would be the
     * number of responders checking the certificate that signed the leaf
     * certificate, and so on. An `authoritative` responder would be any one
     * OCSP responder for a certificate; CRL responders can collectively be
     * considered as one authoritative responder, but individually they are not.
     * Thus, if there were 2 OCSP responders and 2 CRL responders for the leaf
     * certificate, responders_at[0] would return '3'.
     */
    int *responders_at;

    /** The number of active CRL responders peforming revocation check for the
     * certificate at the corresponding index in the cert chain.
     * For example, crl_responders_at[0] would return the number of CRL
     * responders checking the leaf certificate of a chain.
     * @see responders_at.
     */
    int *crl_responders_at;

    int total_to_check; /** Total # certificates in chain that need checking */
    int left_to_check;  /** # certificates in chain not yet checked */

    ocsp_responder* ocsp_responders; /** Array of ocsp responders */
    crl_responder* crl_responders;   /** Array of crl responders */

    X509_STORE* store;     /** Trusted CA certs to verify responses against */
    STACK_OF(X509)* certs; /** Chain of certificates received from peer */
};



struct ocsp_responder_st {

    revocation_ctx* rev_ctx; /** ctx of revocation check being performed */

    struct bufferevent* bev; /** Bufferevent reading/writing OCSP response */
    char* url;               /** OCSP responder's url */

    int cert_position;       /** cert chain position of cert being verified */

    OCSP_CERTID* certid;     /** certificate's ID for the OCSP request/resp */

    unsigned char* buffer;   /** byte buffer to store HTTP response in */
    int buf_size;            /** # of bytes that can be stored in buffer */
    int tot_read;            /** # of bytes currently stored in buffer */
    int is_reading_body;     /** 0 if HTTP header being read, 1 otherwise */

    ocsp_responder* next;    /** Pointer to the next responder in the list */
};

struct crl_responder_st {

    struct bufferevent* bev; /** Bufferevent reading/writing CRL response */
    crl_responder* next;     /** Pointer to the next responder in the list */
};


struct socket_ctx_st {

    daemon_ctx* daemon;     /** The daemon's context */
    unsigned long id;       /** The unique id associated with the socket */
    evutil_socket_t sockfd; /** The file descriptor of the socket */

    enum socket_state state; /** The socket's current state @see socket_state */

    SSL_CTX* ssl_ctx;   /** The context of the SSL object (useful for server) */
    SSL* ssl;           /** The SSL instance associated with \p sockfd */

    int has_shared_context; /** Set if TLS_CONTEXT get/setsockopt used */

    channel plain;      /** The non-encrypted channel to the calling program */
    channel secure;     /** The encrypted channel to the external peer */
    struct evconnlistener* listener; /** Libevent struct for listening socket */

    revocation_ctx rev_ctx; /** Settings/data structs to do with revocation */

    struct sockaddr int_addr; /** Internal address--the program using SSA */
    int int_addrlen;          /** The size of \p int_addr */
    union {
        struct sockaddr ext_addr; /** External address--the remote peer */
        struct sockaddr rem_addr; /** Remote address--the remote host */
    };
    union {
        int ext_addrlen; /** The size of \p ext_addr */
        int rem_addrlen; /** The size of \p rem_addr */
    };
    int local_port; /** Used for temporarily storing connections in daemon */

    char rem_hostname[MAX_HOSTNAME+1]; /** The hostname being connected to */

    char err_string[MAX_ERR_STRING+1]; /** String describing TLS/daemon error */
    unsigned int handshake_err_code;   /** TLS error code for verify failure */
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


/**
 * Creates a string of the format "<hostname>:<port>".
 * @param sock_ctx The socket to retrieve hostname and port information from.
 * @returns A newly allocated null-terminated string.
 */
char* get_hostname_port_str(socket_ctx* sock_ctx);


/**
 * Retrieves an integer port number from a given sockaddr struct.
 * @param addr The sockaddr struct to retrieve the port number of.
 * @returns The port number.
 */
int get_port(struct sockaddr* addr);





#endif
