/**
 * A simple example of a client that implements OpenSSL to connect to a server via internet address
 * and prints Success if it was able to connect securely, or error if the connection was not secure.
 * 
 * This version demonstrates the potential pitfalls of OpenSSL for those who do not know what functions
 * would need to be implemented. The following code appears establish a proper TLS connection, when in
 * reality the least secure settings are used and the implementation is left open to vulnerbilities such
 * as NULL ciphers, self-signed certificates and whatnot.
 * 
 * Written by Nathaniel Bennett
 * Updated 25 February 2020
 * 
 * To Compile: gcc -o <prgm-name> ssl_insecure.c $(pkg-config --libs --cflags openssl)
 * To Run: ./<prgm-name> <domain-name> 
 * 
 *  |-------------------|-------------------|
 *  |     FEATURES      |   IMPLEMENTED?    |
 *  |-------------------|-------------------|
 *  | Secure Encryption | Yes, But Insecure |
 *  | Cert Verification | NO                |
 *  | Error Testing     | None              |
 *  | Concurrency       | None--Blocking    |
 *  | Memory Leak Free? | Maybe             |
 *  | Revocation Checks	| None              |
 *  |   -OCSP Stapling  | "                 |
 *  |   -CRL Checking   | "                 |
 *  |   -OCSP Request   | "                 |
 *
 *
 *  |-----------------------|-------------------|
 *  | SECURITY VULNERBILITY | SECURED AGAINST?  |
 *  |-----------------------|-------------------|
 *  | No Certificate        | NO                |
 *  | Expired Certificate   | NO                |
 *  | Malformed Certificate | NO                |
 *  | Untrusted Root Cert   | NO                |
 *  | Broken Cert Chain     | NO                |
 *  | Revoked Certificate   | NO                |
 *  |   -Bad OCSP Response  | N/A               |
 *  |   -No OCSP/CRL URL    | N/A               |
 *  | Secure Renegotiation  | Yes (Default)     |
 *  | Protocol Downgrading  | NO                |
 *  | Weak MD4/RC5          | NO                |
 *  | SHA1 Certificate      | NO                |
 *  | SHA1 Intermediate Cert| No                |    
 *  | CRIME Attack          | NO                |
 *  | BREACH Attack         | NO                |
 *  
 */

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h> /* for TCP_NODELAY flag in setsockopt() */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

void throw_input_err();
int get_fd(char *hostname, char *port);

/* Port 443 is standard for HTTPS */
#define HTTPS_PORT "443"

int main (int argc, char *argv[]) {
	char *hostname;
	SSL_CTX *ctx;
	SSL *ssl;
    int socket_fd, connect_status;

	if (argc < 2)
		throw_input_err();
	hostname = argv[1]; 

	ctx = SSL_CTX_new(TLS_client_method());
    ssl = SSL_new(ctx);
    socket_fd = get_fd(hostname, HTTPS_PORT);
	SSL_set_fd(ssl, socket_fd);
    
    connect_status = SSL_connect(ssl);
    if (connect_status != 1) {
        fprintf(stderr, "Error occured during the TLS handshake:\n");
		ERR_print_errors_fp(stderr);
        exit(1); /* Fail */
    }
    /* Success! (supposedly) */
    fprintf(stderr, "Handshake succeeded! Connection secured.\n");


    /* This is the part where we have a secure connection and could just send 
     * http requests using SSL_read() and SSL_write()
     */

	/* Part 4: cleanup */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

/*
 **************************************************************************
 * 		HELPER FUNCTIONS NOT SPECIFIC TO OPENSSL
 **************************************************************************
 */

void throw_input_err() {
	printf("\nERROR: insufficient arguments in command.\n");
	printf("Proper usage: ./ssl_simple_client <domain_name>\n");
	exit(1);
}

/* get_fd uses getaddrinfo to create and connect to the proper socket. it returns a file descriptor to a socket. */
int get_fd(char *hostname, char *port) {
	int clientfd;
	struct addrinfo hints, *listp, *p;
	/* Get a list of potential server addresses*/
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_flags |= AI_ADDRCONFIG;

	getaddrinfo(hostname, port, &hints, &listp);

	if (listp == NULL) {
		printf("\nNo addrinfo pointers available to traverse through...\n");
	}
	
	/* Walk the list until one is successfully connected to */
	for (p = listp; p != NULL; p = p->ai_next) {
		if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
			printf("\nSocket failed to create...\n");
			continue; /* Try next socket; this one failed */
		}
		
		if (connect(clientfd, p->ai_addr, p->ai_addrlen) >= 0) {
			break; 
		}
		else {
			printf("\nConnect call failed...\n");
		} 
		
		close(clientfd);
	} 
	
	/* Clean up */
	freeaddrinfo(listp); 

	if (p == NULL) { /* All connections failed */
		printf("\nAll connections failed...\n");
		exit(1);
	}
	return clientfd;
}