#ifndef SSA_IN_TLS
#define SSA_IN_TLS

#ifndef _BITS_SOCKADDR_H
        typedef unsigned short int sa_family_t;
#endif

/* Protocol */
#define IPPROTO_TLS     (715 % 255)

/* Options */

/** The remote hostname of a server a client intends to connect to */
#define TLS_HOSTNAME                      85

/** The CA certificates that a connection will consider as trusted */
#define TLS_TRUSTED_PEER_CERTIFICATES     87

/** The certificate chain to present to a peer during a handshake */
#define TLS_CERTIFICATE_CHAIN             88

/** The private key that goes with the certificate chain used */
#define TLS_PRIVATE_KEY                   89

/** The Aplication-Layer Protocols set to be negotiated for the given socket */
#define TLS_ALPN                          90

/** The maximum time that a session will be considered valid for */
#define TLS_SESSION_TTL                   91

/** A cipher to be marked as unusable for connections */
#define TLS_DISABLE_CIPHER                92

/** The identity of the peer currently connected to (as shown on certificate) */
#define TLS_PEER_IDENTITY                 93

/** Whether or not a certificate will be requested from connecting clients */
#define TLS_REQUEST_PEER_AUTH             94

/** The ciphers that the socket will accept a TLS connection with */
#define TLS_TRUSTED_CIPHERS               97

/** The cipher in use for the current connection */
#define TLS_CHOSEN_CIPHER                 98

/** The error string reported for the last call on the socket */
#define TLS_ERROR                        100

/** Whether or not revocation checks are enabled for the socket */
#define TLS_REVOCATION_CHECKS            102

/** Whether or not OCSP stapling are used as part of revocation checks */
#define TLS_OCSP_STAPLED_CHECKS          103

/** Whether or not OCSP responders are used as part of revocation checks */
#define TLS_OCSP_CHECKS                  104

/** Whether or not CRL checks are used as part of revocation checks */
#define TLS_CRL_CHECKS                   105

/** Whether or not cached revocation responses are used as part of checks */
#define TLS_CACHED_REV_CHECKS            106

/** The settings and sessions associated with a given file descriptor */
#define TLS_CONTEXT                      107

/** Whether or not previous session keys will be cached and reused */ 
#define TLS_SESSION_REUSE                108

/** Whether or not the current connection is based off of a resumed session */
#define TLS_RESUMED_SESSION              109

/** A cipher marked as usable for connections */
#define TLS_ENABLE_CIPHER                110 /* TODO: used to be 109; fix */


/* Internal use only */
#define TLS_PEER_CERTIFICATE_CHAIN        95
#define TLS_ID                            96


/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME     43


/**
 * The SSA_context can be utilized to use the same settings across multiple
 * connections and take full advantage of client-side session caching. It can
 * be retrieved from an SSL connection via the TLS_CONTEXT getsockopt function,
 * and can be inserted into a connection via the TLS_CONTEXT setsockopt function
 * to effectively set all the settings applied to the previous connection. Note
 * that hostnames are not saved within the context--those need to be set for
 * individual connections.
 */
/*
typedef void* SSA_context;
*/

struct host_addr {
        unsigned char name[255]; /* max hostname size in linux */
};

struct sockaddr_host {
        sa_family_t sin_family;
        unsigned short sin_port;
        struct host_addr sin_addr;
};


#endif
