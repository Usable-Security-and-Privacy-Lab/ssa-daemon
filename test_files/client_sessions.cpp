#include <gtest/gtest.h>

#include "testutil/socket_wrappers.h"
#include "testutil/init_tests.h"
#include "testutil/timeouts.h"

#define TWO_FDS 2
#define TEN_FDS 10


INIT_TESTS(ClientSessionTests, "configs/default_localhost.yml", "servers/regular")


TEST_F(ClientSessionTests, OneSocketNoReuse) {

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

TEST_F(ClientSessionTests, TwoTLSContextsNoReuse) {

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

TEST_F(ClientSessionTests, TwoSocketSessionReuse) {

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

        if (i == 0)
            ASSERT_FALSE(resumed);
        else
            ASSERT_TRUE(resumed);
    }

    close(context_fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST_F(ClientSessionTests, TenSocketSessionReuse) {

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

        if (i == 0)
            ASSERT_FALSE(resumed);
        else
            EXPECT_TRUE(resumed);
        
        if (resumed)
            total_resumed++;
    }

    close(context_fd);

    if (total_resumed < 9)
        fprintf(stderr, "Total sessions resumed: %i (expected 9)\n", total_resumed);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST_F(ClientSessionTests, TwoSocketDisabledSessionReuse) {

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

TEST_F(ClientSessionTests, TenSocketDisabledSessionReuse) {

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

TEST_F(ClientSessionTests, DifferentTLSVersionSessionFail) {

    fprintf(stderr, "TODO: need to implement\n");
}

TEST_F(ClientSessionTests, DifferentCipherSessionFail) {

    fprintf(stderr, "TODO: need to implement\n");
}


