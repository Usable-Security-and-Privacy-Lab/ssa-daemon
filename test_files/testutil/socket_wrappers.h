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

#ifndef SSA_HELPER_FUNCTIONS_H
#define SSA_HELPER_FUNCTIONS_H

#include <string>

extern "C" {
#include <unistd.h>
}

#define SHOULD_SUCCEED true
#define SHOULD_FAIL false

#define BLOCKING_SOCKET false
#define NONBLOCKING_SOCKET true

#define LOCALHOST "localhost"
#define LOCAL_PORT "4433"
#define HTTPS_PORT "443"

/**
 * Prints all error information available for the given socket (errno and 
 * potentially TLS_ERROR string).
 * @param fd The file descriptor to print error information for.
 * @param source A string declaring the system call that caused the error.
 */
void print_socket_error(int fd, const std::string source);


/**
 * Performs `getaddrinfo()` DNS resolution on the given host and populates 
 * \p addr and \p addrlen with a viable address to connect to. The address 
 * will be an IPv4 address suitable for a TCP connection.
 * @param host The hostname to perform DNS resolution on.
 * @param addr The returned address of hostname.
 * @param addrlen The length of \p addr.
 */
void resolve_dns(std::string host, std::string port, 
            struct sockaddr** addr, socklen_t* addrlen);


int create_socket(bool is_nonblocking);

void set_hostname(int fd, std::string hostname);
void set_hostname_fail(int fd, std::string hostname, int expected_errno);

void get_hostname(int fd, std::string &hostname);
void get_hostname_fail(int fd, int expected_errno);

void connect_to_host(int fd, std::string hostname, std::string port);
void connect_to_host_fail(int fd, 
            std::string hostname, std::string port, int expected_errno);

void connect_to_localhost(int fd);
void connect_to_localhost_fail(int fd, int expected_errno);

void enable_revocation_checks(int fd, bool should_succeed);
void disable_revocation_checks(int fd, bool should_succeed);

void enable_ocsp_checks(int fd, bool should_succeed);
void disable_ocsp_checks(int fd, bool should_succeed);

void enable_stapled_checks(int fd, bool should_succeed);
void disable_stapled_checks(int fd, bool should_succeed);

void enable_cached_ocsp_checks(int fd, bool should_succeed);
void disable_cached_ocsp_checks(int fd, bool should_succeed);

void get_tls_context(int fd, bool should_succeed, unsigned long* tls_context);
void set_tls_context(int fd, bool should_succeed, unsigned long tls_context);

void disable_session_reuse(int fd, bool should_succeed);
void enable_session_reuse(int fd, bool should_succeed);
void is_resumed_session(int fd, bool should_succeed, bool* is_resumed);


#endif