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

/** TLS version control */
#define TLS_VERSION_MIN                  111
#define TLS_VERSION_MAX                  112
#define TLS_CHOSEN_VERSION               113


#define TLS_SERVER_OCSP_STAPLING         122


#define TLS_1_0 0x00000000
#define TLS_1_1 0x00000001
#define TLS_1_2 0x00000002
#define TLS_1_3 0x00000003



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

#define HOST_ADDR_MAX 120

struct host_addr {
        unsigned char name[HOST_ADDR_MAX]; /* max hostname size in linux */
};

struct sockaddr_host {
        sa_family_t sh_family;
        unsigned short sh_port;
        struct host_addr sh_addr;
};


#endif
