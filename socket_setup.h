/*
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

#ifndef SSA_SOCKET_SETUP_H
#define SSA_SOCKET_SETUP_H

#include "daemon_structs.h"


/**
 * Allocates an SSL_CTX struct and populates it with the settings found in 
 * \p settings. 
 * @param settings a struct filled with the settings that should be applied
 * to the SSL_CTX.
 * @returns A pointer to an allocated SSL_CTX struct, or NULL on error.
 */
SSL_CTX* SSL_CTX_create(global_config* settings);

int test_certificate_authority(char *CA_path);

int prepare_SSL_client(socket_ctx* sock_ctx);


int prepare_SSL_server(socket_ctx* sock_ctx);


/**
 * Allocates and sets the correct settings for the bufferevents of a given 
 * socket. The socket may be either a connecting client socket (in which case 
 * the plain_fd must be set to -1) or an `accept()`ed server socket (in which
 * case the plain_fd must be set to the fd of the socket).
 * @param sock_ctx The context of the socket to prepare bufferevents for.
 * @param plain_fd The file descriptor that will be connected internally to
 * our program.
 * @returns 0 on success, or a negative errno code on failure. The bufferevents 
 * and the plain_fd are cleaned up on failure.
 */
int prepare_bufferevents(socket_ctx* sock_ctx, int plain_fd);


/**
 * Associates the given file descriptor with the given connection and 
 * enables its bufferevent to read and write freely.
 * @param sock_ctx The connection to have the file descriptor associated with.
 * @param ifd The file descriptor of an internal program that will
 * communicate to the daemon through plaintext.
 * @returns 0 on success, or -ECONNABORTED on failure.
 */
int associate_fd(socket_ctx* sock_ctx, evutil_socket_t ifd);

long get_tls_version(enum tls_version version);


#endif
