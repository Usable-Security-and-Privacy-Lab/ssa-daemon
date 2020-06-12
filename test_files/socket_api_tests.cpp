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

}

extern "C" {

    #define HOSTNAME "www.yahoo.com"
    #define PORT "443"
}


class SocketAPITests : public testing::Test {
public:
    struct sockaddr* address;
    socklen_t addrlen;

    virtual void SetUp() {
        struct addrinfo hints = {0};

        result = NULL;

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;

        getaddrinfo(HOSTNAME, PORT, &hints, &result);

        if (result == NULL) {
            printf("Couldn't resolve DNS.\n");
            exit(1);
        }

        address = result->ai_addr;
        addrlen = result->ai_addrlen;
    }

    virtual void TearDown() {
        freeaddrinfo(result);
    }

private:
    struct addrinfo* result;
};



void print_socket_error(int fd) {

    char buf[256] = {0};
    socklen_t buf_len = 255;
    int ret;

    ret = getsockopt(fd, IPPROTO_TLS, TLS_ERROR, buf, &buf_len);
    if (ret == 0)
        fprintf(stderr, "System call failed--errno %i, err string: %s\n",
                    errno, buf);
    else
        fprintf(stderr, "System call failed with errno %i: %s\n", 
                    errno, strerror(errno));
}

/*******************************************************************************
 *                              TEST CASES
 ******************************************************************************/



TEST_F(SocketAPITests, DoubleConnectFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME,
                HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    int second_connect_ret = connect(fd, address, addrlen);

    EXPECT_EQ(second_connect_ret, -1);
    EXPECT_EQ(errno, EISCONN);

    if (second_connect_ret == -1)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)

}

TEST_F(SocketAPITests, ConnectThenListenFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME,
                HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    int listen_ret = listen(fd, SOMAXCONN);

    EXPECT_EQ(listen_ret, -1);
    EXPECT_EQ(errno, EOPNOTSUPP);

    if (listen_ret == -1)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}



TEST_F(SocketAPITests, ConnectThenBindFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME,
                HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    
    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);
    
    struct sockaddr_in int_addr = {0};
    
    int_addr.sin_family = AF_INET;
    int_addr.sin_port = 0;
    int_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
 

    int bind_ret = bind(fd, (struct sockaddr*) &int_addr, sizeof(sockaddr_in));

    EXPECT_EQ(bind_ret, -1);
    EXPECT_EQ(errno, EINVAL);

    if (bind_ret == -1)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)

}


TEST_F(SocketAPITests, ConnectThenAcceptFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME,
                HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_socket_error(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    /* bad address to bind to, but shouldn't matter */
    struct sockaddr temp_addr;
    socklen_t temp_addrlen;
    int accept_ret = accept(fd, &temp_addr, &temp_addrlen);

    EXPECT_EQ(accept_ret, -1);
    EXPECT_EQ(errno, EINVAL);

    if (accept_ret == -1)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

























