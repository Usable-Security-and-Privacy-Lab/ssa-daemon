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

TEST_F(SocketAPITests, SocketCreation) {

    int socket_return = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_GT(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketAPITests, SocketWrongDomain) {

    int socket_return = socket(AF_NETLINK, SOCK_STREAM, IPPROTO_TLS);

    EXPECT_EQ(socket_return, -1);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketAPITests, SocketWrongType) {
    /* TODO: someday we'll implement DTLS. this should be changed then */

    int socket_return = socket(AF_NETLINK, SOCK_DGRAM, IPPROTO_TLS);

    EXPECT_EQ(socket_return, -1);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketAPITests, SocketWithNonblockType) {

    int socket_return = socket(AF_INET, 
                SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_GE(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketAPITests, ConnectWithNonblockSocket) {

    int socket_return = socket(AF_INET, 
                SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    socket_errno, strerror(socket_errno));

    ASSERT_GE(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    /* TODO: test the errno here too */


    int hostname_setsockopt_return = setsockopt(socket_return, 
                IPPROTO_TLS, TLS_REMOTE_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    if (hostname_setsockopt_return != 0) {
        fprintf(stderr, "Hostname setsockopt failed with errno %i: %s\n",
                    hostname_errno, strerror(hostname_errno));
        close(socket_return);
    }
    
    ASSERT_EQ(hostname_setsockopt_return, 0);
    EXPECT_EQ(hostname_errno, 0);

    int connect_return = connect(socket_return, address, addrlen);
    int connect_errno = errno;

    EXPECT_EQ(connect_return, -1);
    EXPECT_EQ(connect_errno, EINPROGRESS);
    if (connect_return != -1)
        fprintf(stderr, "Connect returned 0 (should block)\n");
    else if (connect_errno != EINPROGRESS)
        fprintf(stderr, "Connect errno was %i: %s\n", 
                    connect_errno, strerror(connect_errno));

    close(socket_return);
}


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

























