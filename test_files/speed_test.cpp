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

#include <gtest/gtest.h>

#include "testutil/socket_wrappers.h"
#include "testutil/init_tests.h"
#include "testutil/timeouts.h"

extern "C" {

#include <sys/time.h>

}


INIT_TESTS_NO_VALGRIND(SpeedBenchmark, "configs/default_localhost.yml", "servers/regular")

TEST_F(SpeedBenchmark, NoSessionReuse) {

    struct timeval start, stop;  
    double total_secs = 0;
    int fd;

    /* Done so that no DNS resolving will performed during test */
    fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);
    close(fd);

    for (int i = 0; i < 1000; i++) {

        fd = create_socket(BLOCKING_SOCKET);
        if (fd < 0)
            FAIL();
    
        set_hostname(fd, LOCALHOST);

        gettimeofday(&start, NULL);
        connect_to_localhost(fd);
        gettimeofday(&stop, NULL);
        total_secs += (double)(stop.tv_usec - start.tv_usec) / 1000000 
                   + (double)(stop.tv_sec - start.tv_sec);

        close(fd);
    }

    printf("\nTotal time (1000 TCP/TLS handshakes, session resumption off): %fs\n", total_secs);
    printf("Average time: %fs\n\n", (total_secs / 1000));
}


TEST_F(SpeedBenchmark, SessionReuse) {

    struct timeval start, stop;  
    double total_secs = 0;
    unsigned long tls_context = 0;
    int context_fd, fd;

    /* Done so that no DNS resolving will performed during test */
    fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);
    close(fd);

    context_fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(context_fd, LOCALHOST);
    get_tls_context(context_fd, SHOULD_SUCCEED, &tls_context);

    for (int i = 0; i < 1000; i++) {

        fd = create_socket(BLOCKING_SOCKET);
        if (fd < 0)
            FAIL();
    
        set_tls_context(fd, SHOULD_SUCCEED, tls_context);

        gettimeofday(&start, NULL);
        connect_to_localhost(fd);
        gettimeofday(&stop, NULL);
        total_secs += (double)(stop.tv_usec - start.tv_usec) / 1000000 
                   + (double)(stop.tv_sec - start.tv_sec);

        close(fd);
    }

    printf("\nTotal time (1000 TCP/TLS handshakes, session resumption on): %fs\n", total_secs);
    printf("Average time: %fs\n\n", (total_secs / 1000));
}