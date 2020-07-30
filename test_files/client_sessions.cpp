#include <gtest/gtest.h>

#include "helper_functions.h"
#include "timeouts.h"

#define TWO_FDS 2
#define TEN_FDS 10



class ClientSessionTests : public testing::Test {
public:
    unsigned long tls_context;
    unsigned long sessionless_context;
    int context_fd;
    int no_sessions_fd;

    
    static void SetUpTestSuite() {
        /* TODO: launch server here via fork(), execve() */
    }


    virtual void SetUp() {
        
        context_fd = create_socket(BLOCKING_SOCKET);
        if (context_fd < 0)
            FAIL();
        set_hostname(context_fd, LOCALHOST);

        get_tls_context(context_fd, SHOULD_SUCCEED, &tls_context);

        no_sessions_fd = create_socket(BLOCKING_SOCKET);
        if (no_sessions_fd < 0)
            FAIL();

        set_hostname(no_sessions_fd, LOCALHOST);
        disable_session_reuse(no_sessions_fd, SHOULD_SUCCEED);
        get_tls_context(no_sessions_fd, SHOULD_SUCCEED, &sessionless_context);       

    }

    virtual void TearDown() {
        if (context_fd >= 0)
            close(context_fd);
        if (no_sessions_fd >= 0)
            close(no_sessions_fd);
    }

    
    static void TearDownTestSuite() {
        /* TODO: send kill() signal to server */
    }
};


TEST_F(ClientSessionTests, OneSocketNoReuse) {

    bool reused = false;

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();
    
    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);
    is_resumed_session(fd, SHOULD_SUCCEED, &reused);

    close(fd);
    ASSERT_FALSE(reused);
}

TEST_F(ClientSessionTests, TwoTLSContextsNoReuse) {

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
}

TEST_F(ClientSessionTests, TwoSocketSessionReuse) {

    bool resumed = false;
    int fds[TWO_FDS];

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
}

TEST_F(ClientSessionTests, TenSocketSessionReuse) {

    int total_resumed = 0;
    bool resumed = false;
    int fds[TEN_FDS];

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

    if (total_resumed < 9)
        fprintf(stderr, "Total sessions resumed: %i\n", total_resumed);
}

TEST_F(ClientSessionTests, TwoSocketDisabledSessionReuse) {

    bool resumed = true;
    int fds[TWO_FDS];

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = create_socket(BLOCKING_SOCKET);
        if (fds[i] < 0)
            FAIL();

        set_tls_context(fds[i], SHOULD_SUCCEED, tls_context);
        disable_session_reuse(fds[i], SHOULD_SUCCEED);
        connect_to_localhost(fds[i]);

        is_resumed_session(fds[i], SHOULD_SUCCEED, &resumed);
        close(fds[i]);

        ASSERT_FALSE(resumed);
    }
}

TEST_F(ClientSessionTests, TenSocketDisabledSessionReuse) {
    
    bool resumed = true;
    int fds[TEN_FDS];

    for (int i = 0; i < TEN_FDS; i++) {
        fds[i] = create_socket(BLOCKING_SOCKET);
        if (fds[i] < 0)
            FAIL();

        set_tls_context(fds[i], SHOULD_SUCCEED, sessionless_context);
        connect_to_localhost(fds[i]);

        is_resumed_session(fds[i], SHOULD_SUCCEED, &resumed);
        close(fds[i]);

        ASSERT_FALSE(resumed);
    }
}

TEST_F(ClientSessionTests, DifferentTLSVersionSessionFail) {

    fprintf(stderr, "TODO: need to implement\n");
}

TEST_F(ClientSessionTests, DifferentCipherSessionFail) {

    fprintf(stderr, "TODO: need to implement\n");
}


