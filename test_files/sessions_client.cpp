#include <gtest/gtest.h>


#include "timeouts.h"


/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include "../in_tls.h"

#include "helper_functions.h"

#define TWO_FDS 2
#define TEN_FDS 10

const char* HOSTNAME  = "ebay.com"; /* Does sessions :thumbsup: */
const char* PORT = "443";

const char* ERR_SOURCE_GET_CONTEXT = "TLS_CONTEXT getsockopt()";
const char* ERR_SOURCE_SET_HOSTNAME = "TLS_HOSTNAME setsockopt()";
const char* ERR_SOURCE_CONNECT = "connect()";
const char* ERR_SOURCE_SESS_RESUMED = "TLS_RESUMED_SESSION getsockopt()";
}


class ClientSessionTests : public testing::Test {
public:
    struct sockaddr* address;
    socklen_t addrlen;
    unsigned long tls_context;

    ClientSessionTests() {

        int hostname_ret, tls_context_ret;
        socklen_t tls_ctx_size = sizeof(tls_context);

        int ret = resolve_dns(HOSTNAME, PORT, &address, &addrlen);
        if (ret != 0)
            goto err;

        context_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (context_fd < 0) {
            perror("socket() failed");
            goto err;
        }

        hostname_ret = setsockopt(context_fd, IPPROTO_TLS, 
                    TLS_HOSTNAME, &HOSTNAME, strlen(HOSTNAME)+1);
        if (hostname_ret != 0) {
            print_socket_error(tls_context, ERR_SOURCE_SET_HOSTNAME);
            goto err;
        }

        /* IMPORTANT: This code operates under the assumption that rigorous 
         * tests have already been performed on the TLS_CONTEXT getsockopt.
         * Without it, client-side session caching is basically impossible,
         * so it is used in every test of this test suite.
         */
        tls_context_ret = getsockopt(context_fd, 
                    IPPROTO_TLS, TLS_CONTEXT, &tls_context, &tls_ctx_size);
        if (tls_context_ret != 0) {
            print_socket_error(context_fd, ERR_SOURCE_GET_CONTEXT);
            goto err;
        }

        return;
    err:
        printf("An unrecoverable error occurred in SessionTests setup\n");
        exit(1);
    }

    ~ClientSessionTests() {
        if (address != NULL)
            free(address);
        if (context_fd >= 0)
            close(context_fd);
    }

private:
    int context_fd;
};


TEST_F(ClientSessionTests, OneSocketNoReuse) {

    int session_reused;
    socklen_t int_len = sizeof(int);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        perror("socket() failed");

    int hostname_ret = setsockopt(fd, IPPROTO_TLS, 
                TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    if (hostname_ret != 0)
        print_socket_error(fd, ERR_SOURCE_SET_HOSTNAME);
    
    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    int connect_errno = errno;

    if (connect_ret != 0)
        print_socket_error(fd, ERR_SOURCE_CONNECT);

    EXPECT_EQ(connect_errno, 0);
    ASSERT_EQ(connect_errno, 0);

    int session_reused_ret = getsockopt(fd, IPPROTO_TLS,
                TLS_RESUMED_SESSION, &session_reused, &int_len);
    int session_reused_errno = errno;

    if (session_reused_ret != 0)
        print_socket_error(fd, ERR_SOURCE_SESS_RESUMED);

    EXPECT_EQ(session_reused_errno, 0);
    ASSERT_EQ(session_reused_ret, 0);

    ASSERT_EQ(session_reused, 0);

    close(fd);
}

TEST_F(ClientSessionTests, TwoTLSContextsNoReuse) {

    int session_reused;
    socklen_t int_len = sizeof(int);
    int fds[TWO_FDS];

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
        if (fds[i] < 0)
            perror("socket() failed");

        int hostname_ret = setsockopt(fds[i], IPPROTO_TLS, 
                    TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        if (hostname_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SET_HOSTNAME);
        
        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_ret, 0);

        int connect_ret = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        if (connect_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_CONNECT);

        EXPECT_EQ(connect_errno, 0);
        ASSERT_EQ(connect_errno, 0);

        int session_reused_ret = getsockopt(fds[i], IPPROTO_TLS,
                    TLS_RESUMED_SESSION, &session_reused, &int_len);
        int session_reused_errno = errno;

        if (session_reused_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SESS_RESUMED);

        EXPECT_EQ(session_reused_errno, 0);
        ASSERT_EQ(session_reused_ret, 0);

        ASSERT_EQ(session_reused, 0);
    }

    for (int i = 0; i < TWO_FDS; i++)
        close(fds[i]);
}

TEST_F(ClientSessionTests, TwoSocketSessionReuse) {

    int session_reused;
    socklen_t int_len = sizeof(int);
    int fds[TWO_FDS];

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
        if (fds[i] < 0)
            perror("socket() failed");

        int context_ret = setsockopt(fds[i], IPPROTO_TLS, 
                    TLS_CONTEXT, &tls_context, sizeof(tls_context));
        int context_errno = errno;

        if (context_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SET_HOSTNAME);
        
        EXPECT_EQ(context_errno, 0);
        ASSERT_EQ(context_ret, 0);

        int connect_ret = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        if (connect_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_CONNECT);

        EXPECT_EQ(connect_errno, 0);
        ASSERT_EQ(connect_errno, 0);

        int session_reused_ret = getsockopt(fds[i], IPPROTO_TLS,
                    TLS_RESUMED_SESSION, &session_reused, &int_len);
        int session_reused_errno = errno;

        if (session_reused_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SESS_RESUMED);

        EXPECT_EQ(session_reused_errno, 0);
        ASSERT_EQ(session_reused_ret, 0);
        
        if (i == 0)
            ASSERT_EQ(session_reused, 0);
        else
            ASSERT_EQ(session_reused, 1);
    }

    for (int i = 0; i < TWO_FDS; i++)
        close(fds[i]);
}

TEST_F(ClientSessionTests, TenSocketSessionReuse) {

    int num_sessions_reused = 0;
    int session_reused;
    socklen_t int_len = sizeof(int);
    int fds[TEN_FDS];

    for (int i = 0; i < TWO_FDS; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
        if (fds[i] < 0)
            perror("socket() failed");

        int context_ret = setsockopt(fds[i], IPPROTO_TLS, 
                    TLS_CONTEXT, &tls_context, sizeof(tls_context));
        int context_errno = errno;

        if (context_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SET_HOSTNAME);
        
        EXPECT_EQ(context_errno, 0);
        ASSERT_EQ(context_ret, 0);

        int connect_ret = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        if (connect_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_CONNECT);

        EXPECT_EQ(connect_errno, 0);
        ASSERT_EQ(connect_errno, 0);

        int session_reused_ret = getsockopt(fds[i], IPPROTO_TLS,
                    TLS_RESUMED_SESSION, &session_reused, &int_len);
        int session_reused_errno = errno;

        if (session_reused_ret != 0)
            print_socket_error(fds[i], ERR_SOURCE_SESS_RESUMED);

        EXPECT_EQ(session_reused_errno, 0);
        ASSERT_EQ(session_reused_ret, 0);

        ASSERT_GE(session_reused, 0);
        ASSERT_LE(session_reused, 1);
        
        if (i == 0)
            ASSERT_EQ(session_reused, 0);
        else
            num_sessions_reused += session_reused;
    }

    ASSERT_GT(num_sessions_reused, 0);

    printf("Total sessions reused: %i\n", num_sessions_reused);

    for (int i = 0; i < TEN_FDS; i++)
        close(fds[i]);
}

TEST_F(ClientSessionTests, TwoSocketDisabledSessionReuse) {

}

TEST_F(ClientSessionTests, TenSocketDisabledSessionReuse) {

}

TEST_F(ClientSessionTests, DifferentTLSVersionSessionFail) {

}

TEST_F(ClientSessionTests, DifferentCipherSessionFail) {

}


