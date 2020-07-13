#ifndef SSA_IN_TLS
#define SSA_IN_TLS

#ifndef _BITS_SOCKADDR_H
        typedef unsigned short int sa_family_t;
#endif

/* Protocol */
#define IPPROTO_TLS     (715 % 255)

/* Options */
#define TLS_REMOTE_HOSTNAME               85
#define TLS_HOSTNAME                      86
#define TLS_TRUSTED_PEER_CERTIFICATES     87
#define TLS_CERTIFICATE_CHAIN             88
#define TLS_PRIVATE_KEY                   89
#define TLS_ALPN                          90
#define TLS_SESSION_TTL                   91
#define TLS_DISABLE_CIPHER                92
#define TLS_PEER_IDENTITY                 93
#define TLS_REQUEST_PEER_AUTH             94

/* Internal use only */
#define TLS_PEER_CERTIFICATE_CHAIN        95
#define TLS_ID                            96

#define TLS_TRUSTED_CIPHERS               97
#define TLS_CHOSEN_CIPHER                 98
#define TLS_ERROR                        100
#define TLS_DISABLE_COMPRESSION          101

#define TLS_REVOCATION_CHECKS            102
#define TLS_OCSP_STAPLED_CHECKS          103
#define TLS_OCSP_CHECKS                  104 
#define TLS_CRL_CHECKS                   105 
#define TLS_CACHE_REVOCATION             106


/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME     43

struct host_addr {
        unsigned char name[255]; /* max hostname size in lunux */
};

struct sockaddr_host {
        sa_family_t sin_family;
        unsigned short sin_port;
        struct host_addr sin_addr;
};


#endif

