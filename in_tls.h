#ifndef IN_TLS
#define IN_TLS

/* Protocol */
#define IPPROTO_TLS 	(715 % 255)

/* Options */
#define SO_REMOTE_HOSTNAME               85
#define SO_HOSTNAME                      86
#define SO_TRUSTED_PEER_CERTIFICATES     87
#define SO_CERTIFICATE_CHAIN             88
#define SO_PRIVATE_KEY                   89
#define SO_ALPN                          90
#define SO_SESSION_TTL                   91
#define SO_DISABLE_CIPHER                92
#define SO_PEER_CERTIFICATE              93
#define SO_ID                            94

/* TCP options */
#define TCP_UPGRADE_TLS         33

/* Address types */
#define AF_HOSTNAME	43

struct host_addr { 
	unsigned char name[255]; 
}; 
 
struct sockaddr_host { 
	sa_family_t sin_family; 
	unsigned short sin_port; 
	struct host_addr sin_addr; 
}; 


#endif
