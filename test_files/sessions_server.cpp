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

#define TWO_FDS 2
#define TEN_FDS 10


INIT_TESTS(ServerSessionTests, "configs/default_localhost.yml", "servers/no_sessions")


TEST_F(ServerSessionTests, OneSocketNoReuse) {

    TEST_TIMEOUT_BEGIN

    bool reused = false;

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();
    
    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);
    is_resumed_session(fd, SHOULD_SUCCEED, &reused);

    close(fd);
    ASSERT_FALSE(reused);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST_F(ServerSessionTests, TwoTLSContextsNoReuse) {

    TEST_TIMEOUT_BEGIN

    bool reused = false;
    int fds[TWO_FDS];

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = create_socket(BLOCKING_SOCKET);
        if (fds[i] < 0)
            FAIL();

        set_hostname(fds[i], LOCALHOST);
        connect_to_localhost(fds[i]);

        is_resumed_session(fds[i], SHOULD_SUCCEED, &reused);

        close(fds[i]);
        ASSERT_FALSE(reused);
    }

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST_F(ServerSessionTests, TwoSocketSessionReuse) {

    TEST_TIMEOUT_BEGIN

    unsigned long tls_context;
    bool resumed = false;
    int fds[TWO_FDS];
    int context_fd;

    context_fd = create_socket(BLOCKING_SOCKET);
    if (context_fd < 0)
        FAIL();
    set_hostname(context_fd, LOCALHOST);
    get_tls_context(context_fd, SHOULD_SUCCEED, &tls_context);

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = create_socket(BLOCKING_SOCKET);

        set_tls_context(fds[i], SHOULD_SUCCEED, tls_context);
        connect_to_localhost(fds[i]);

        is_resumed_session(fds[i], SHOULD_SUCCEED, &resumed);
        close(fds[i]);

        ASSERT_FALSE(resumed);
    }

    close(context_fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST_F(ServerSessionTests, TenSocketSessionReuse) {

    TEST_TIMEOUT_BEGIN

    unsigned long tls_context;
    int total_resumed = 0;
    bool resumed = false;
    int fds[TEN_FDS];
    int context_fd;
    
    context_fd = create_socket(BLOCKING_SOCKET);
    if (context_fd < 0)
        FAIL();
    set_hostname(context_fd, LOCALHOST);
    get_tls_context(context_fd, SHOULD_SUCCEED, &tls_context);

    for (int i = 0; i < TEN_FDS; i++) {
        fds[i] = create_socket(BLOCKING_SOCKET);

        set_tls_context(fds[i], SHOULD_SUCCEED, tls_context);
        connect_to_localhost(fds[i]);

        is_resumed_session(fds[i], SHOULD_SUCCEED, &resumed);
        close(fds[i]);

        EXPECT_FALSE(resumed);

        if (resumed)
            total_resumed++;
    }

    close(context_fd);

    if (total_resumed > 0)
        fprintf(stderr, "Total sessions resumed: %i (expected 0)\n", total_resumed);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

TEST_F(ServerSessionTests, TwoSocketDisabledSessionReuse) {

    TEST_TIMEOUT_BEGIN

    unsigned long sessionless_context;
    bool resumed = true;
    int fd, no_sessions_fd;


    no_sessions_fd = create_socket(BLOCKING_SOCKET);
    if (no_sessions_fd < 0)
        FAIL();

    set_hostname(no_sessions_fd, LOCALHOST);
    disable_session_reuse(no_sessions_fd, SHOULD_SUCCEED);
    get_tls_context(no_sessions_fd, SHOULD_SUCCEED, &sessionless_context);


    for (int i = 0; i < TWO_FDS; i++) {
        fd = create_socket(BLOCKING_SOCKET);
        if (fd < 0)
            FAIL();

        set_tls_context(fd, SHOULD_SUCCEED, sessionless_context);
        connect_to_localhost(fd);

        is_resumed_session(fd, SHOULD_SUCCEED, &resumed);
        close(fd);

        ASSERT_FALSE(resumed);
    }

    close(no_sessions_fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

TEST_F(ServerSessionTests, TenSocketDisabledSessionReuse) {

    TEST_TIMEOUT_BEGIN
    
    unsigned long sessionless_context;
    bool resumed = true;
    int fd;
    int no_sessions_fd;

    no_sessions_fd = create_socket(BLOCKING_SOCKET);
    if (no_sessions_fd < 0)
        FAIL();

    set_hostname(no_sessions_fd, LOCALHOST);
    disable_session_reuse(no_sessions_fd, SHOULD_SUCCEED);
    get_tls_context(no_sessions_fd, SHOULD_SUCCEED, &sessionless_context);


    for (int i = 0; i < TEN_FDS; i++) {
        fd = create_socket(BLOCKING_SOCKET);
        if (fd < 0)
            FAIL();

        set_tls_context(fd, SHOULD_SUCCEED, sessionless_context);
        connect_to_localhost(fd);

        is_resumed_session(fd, SHOULD_SUCCEED, &resumed);
        close(fd);

        ASSERT_FALSE(resumed);
    }

    close(no_sessions_fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_VERY_LONG)
}

