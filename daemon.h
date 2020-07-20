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
#ifndef SSA_DAEMON_H
#define SSA_DAEMON_H

#include <sys/socket.h>

#include "daemon_structs.h"



/**
 * Performs all of the steps needed to run the SSA daemon: estabilshes
 * a netlink connection with the kernel module, begins listening on the given 
 * port for connections, and runs the libevent event base indefinitely.
 * This function only returns if an unrecoverable error occurred in the
 * daemon, or if a SIGINT signal was sent to the process.
 * @param port The port to listen on for new connections.
 * @param config_path A NULL-terminated string identifying the file path
 * of a .yml configuration for the daemon.
 * @returns EXIT_SUCCESS (0) if the event base ran for some indeterminate
 * amount of time successfully, or EXIT_FAILURE (1) if an error occurred
 * before the event base could run.
 */
int run_daemon(int port, char* config_path);


/**
 * The callback invoked when an internal program calls socket() with the
 * IPPROTO_TLS option. This function creates a socket within the daemon
 * that mirrors any settings or functionality set by the internal program.
 * That socket is added to a hashmap (sock_map), and is used to establish
 * encrypted connections with the external peer via TLS protocols.
 * @param daemon A pointer to the program's daemon_ctx.
 * @param id A uniquely generated ID for the given socket; corresponds with
 * (though is not equal to) the internal program's file descriptor of that
 * socket.
 * @param comm The address path of the calling program.
 * @returns (via netlink) a notification of 0 on success, or -errno on failure.
 */
void socket_cb(daemon_ctx* ctx, unsigned long id, char* comm);


/**
 * The callback invoked when an internal program calls `getsockopt()` on a 
 * socket created with the `IPPROTO_TLS` protocol. It is intended as the 
 * interface that a programmer may use to modify socket behavior within a 
 * user space program utilizing the SSA daemon.
 * @param ctx The context of the daemon (contains hashmaps of socket contexts
 * and other important data).
 * @param id The id of the socket to invoke the operation on.
 * @param level The layer to set socket information for. The IPPROTO_TLS layer
 * directly deals with TLS configurations on an individual socket within the 
 * daemon; other options are still passed through here so that the daemon's
 * internal socket will mirror the functionality of the program's socket.
 * @param option The desired socket option to modify. Socket options may be
 * get-only or set-only, depending on their functionality. See the documentation
 * on `setsockopt()` for more info on individual options.
 * @param value The data to be set for the given option.
 * @param len The byte length of \p value
 * @returns (via Netlink) a notification of 0 on success, or -errno on failure.
 */
void setsockopt_cb(daemon_ctx* ctx, unsigned long id, int level, 
		int option, void* value, socklen_t len);


/**
 * The callback invoked whenever a program uses the `getsockopt()` system call
 * with `level` set to `IPPROTO_TLS`. This callback only deals specifically with
 * that level; other layers are dealt with by the kernel module.
 * @param daemon The context of the daemon (contains hashmaps of socket contexts
 * and other important data).
 * @param id The id of the socket to retrieve information from.
 * @param level The level of the socket operation (should always be 
 * `IPPROTO_TLS`).
 * @param option The desired socket option to retrieve information on.
 * @returns (via Netlink) a notification of 0 on success, or -errno on failure.
 */
void getsockopt_cb(daemon_ctx* ctx, unsigned long id, int level, int option);



/**
 * The callback executed whenever `bind()` is called on a TLS socket.
 * This is necessary as it is the daemon's internal socket that actually
 * needs to bind to the specified address rather than the socket of the 
 * program calling the system call.
 * @param daemon The context of the current running daemon.
 * @param id The id of the socket to bind.
 * @param int_addr The address that the calling program's socket will be bound 
 * to.
 * @param int_addrlen The size of int_addr.
 * @param ext_addr The address that the daemon's socket should bind to.
 * This is what the user actually passes in when they call `bind()`.
 * @param ext_addrlen The length of ext_addr.
 * @returns (via Netlink) a notification of 0 on success, or -errno on failure.
 */
void bind_cb(daemon_ctx* ctx, unsigned long id, struct sockaddr* int_addr, 
            int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);



/**
 * Begins an attempt to connect via TLS to the remote host. Upon completion,
 * the function client_bev_event_cb() will be called with the appropriate events
 * (BEV_EVENT_CONNECTED on success, BEV_EVENT_ERROR on failure). Since the
 * daemon's internal sockets are always set to non-blocking, this function
 * does not notify the kernel (unless a failure happened from within the
 * function); that is left up to the callback function.
 * @param daemon_ctx The daemon context associated with this daemon.
 * @param id The ID of the socket to attempt to connect. This is used along
 * with a hashmap (sock_map) found in the daemon context in order to retrieve
 * the context specific to the socket the calling program is using.
 * @param int_addr The address of the socket used by the calling program.
 * @param int_addrlen The length of int_addr.
 * @param ext_addr The address of the server we're attempting to connect to.
 * @param ext_addrlen The length of ext_addr.
 * @param blocking Set as 1 if the calling program's socket is blocking, or 0
 * if it is set as non-blocking. If it is non-blocking, then this function
 * will notify the kernel with the EINPROGRESS errno code before returning.
 * @return No return value--meant to send a netlink message if something is
 * to be returned.
 */
void connect_cb(daemon_ctx* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen, int blocking);



/**
 * Assigns the socket associated with \p id to listen for incoming connections.
 * Both this and the calling program's internal socket will be listening; this
 * socket will automatically accept and perform TLS handshakes for new 
 * connections, whereas the calling program's socket will only establish new 
 * connections whenever `accept()` is called.
 * @param daemon The context of this daemon.
 * @param id The id of the socket to set to listen.
 * @param int_addr The address that the calling program's socket has been 
 * assigned to (??).
 * @param int_addrlen The size of int_addr.
 * @param ext_addr The address that the daemon's socket has been assigned to 
 * (?).
 * @param ext_addrlen The size of ext_addr.
 * @returns (via Netlink) a notification of 0 for success, or -errno for errors.
 */
void listen_cb(daemon_ctx* ctx, unsigned long id, struct sockaddr* int_addr,
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);


/**
 * Finishes the process of accepting an incoming client connection.
 * This function is only called after the calling program calls accept()
 * and a TLS connection has been successfully made between the incoming
 * client and the daemon's internal socket. The purpose of this function
 * is to associate an id with the sock_ctx of the already accepted connection
 * so that the internal user can begin to communicate via the daemon to the
 * client.
 * @param daemon The context of the daemon.
 * @param id A unique id generated by the SSA kernel module that can be assigned 
 * to the associated socket.
 * @param int_addr (??)
 * @param int_addrlen The size of \p int_addr.
 */
void associate_cb(daemon_ctx* ctx, unsigned long id, struct sockaddr* int_addr,
	       	int int_addrlen);


/**
 * Closes and frees all internal file descriptors and buffers associated
 * with a socket in the daemon. When a calling program is terminated, the SSA 
 * kernel module will trigger this close_cb on every open file descriptor in
 * that program.
 * @param daemon The context of the daemon.
 * @param id The id of the socket to be closed.
 */
void close_cb(daemon_ctx* ctx, unsigned long id);

#endif
