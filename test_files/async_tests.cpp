#include <gtest/gtest.h>

#include "timeouts.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include "../in_tls.h"

}

extern "C" {

    #define HOSTNAME "www.yahoo.com"
    #define PORT "443"
}



class AsyncTests : public testing::Test {
public:
    struct sockaddr* address;
    socklen_t addrlen;

    int fd;

    AsyncTests() {
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

    ~AsyncTests() {
        freeaddrinfo(result);
    }

    virtual void SetUp() {
        fd = -1;
    }

    virtual void TearDown() {

        if (fd != -1)
            close(fd);
    }


private:
    struct addrinfo* result;
};

void print_socket_error(int fd) {

    char reason[256] = {0};
    socklen_t reason_len = 256;
    int error;
    socklen_t error_len = sizeof(error);
    int ret;

    fprintf(stderr, "System call failed.\n");
    fprintf(stderr, "Current errno code is %i: %s\n", errno, strerror(errno));

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len);
    if (ret == 0)
        fprintf(stderr, "Getsockopt errno code is %i: %s\n",
                    error, strerror(error));
    else
        fprintf(stderr, "Couldn't get getsockopt errno code\n");

    ret = getsockopt(fd, IPPROTO_TLS,
                TLS_ERROR, reason, &reason_len);
    if (ret != 0)
        fprintf(stderr, "Couldn't get TLS error string\n");
    else
        fprintf(stderr, "TLS error string: %s\n", reason);
}


TEST_F(AsyncTests, PollSocketConnect) {

    int fd = socket(AF_INET, 
                SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    socket_errno, strerror(socket_errno));

    EXPECT_EQ(socket_errno, 0);
    ASSERT_GE(fd, 0);

    int hostname_setsockopt_return = setsockopt(fd, 
                IPPROTO_TLS, TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    if (hostname_setsockopt_return != 0)
        print_socket_error(fd);

    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_setsockopt_return, 0);

    int connect_return = connect(fd, address, addrlen);
    int connect_errno = errno;

    if (connect_return == -1 && errno != EINPROGRESS)
        print_socket_error(fd);

    EXPECT_EQ(connect_errno, EINPROGRESS);
    ASSERT_EQ(connect_return, -1);

    struct pollfd fdstruct = {0};
    fdstruct.fd = fd;
    fdstruct.events = POLLIN | POLLOUT | POLLERR | POLLPRI | POLLHUP;

    int poll_return = poll(&fdstruct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    if (fdstruct.revents & POLLERR)
        print_socket_error(fd);

    ASSERT_FALSE(fdstruct.revents & POLLERR);
    ASSERT_FALSE(fdstruct.revents & POLLHUP);
    ASSERT_FALSE(fdstruct.revents & POLLNVAL);
    ASSERT_FALSE(fdstruct.revents & POLLPRI);

    if (!(fdstruct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fdstruct.revents & POLLIN);
    ASSERT_TRUE(fdstruct.revents & POLLOUT);

    int connect_2nd_return = connect(fd, address, addrlen);
    int connect_2nd_errno = errno;

    EXPECT_EQ(connect_2nd_return, -1);
    EXPECT_EQ(connect_2nd_errno, EISCONN);
        
}


TEST_F(AsyncTests, PollSocketConnectRead) {

    int socket_fd = socket(AF_INET, 
                SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (socket_fd < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n", 
                    socket_errno, strerror(socket_errno));

    EXPECT_EQ(socket_errno, 0);
    ASSERT_GE(socket_fd, 0);

    int hostname_setsockopt_return = setsockopt(socket_fd, 
                IPPROTO_TLS, TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    if (hostname_setsockopt_return != 0)
        print_socket_error(socket_fd);

    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_setsockopt_return, 0);

    int connect_return = connect(socket_fd, address, addrlen);
    int connect_errno = errno;

    if (connect_return == -1 && errno != EINPROGRESS)
        print_socket_error(socket_fd);

    ASSERT_EQ(connect_return, -1);
    ASSERT_EQ(connect_errno, EINPROGRESS);

    struct pollfd fdstruct = {0};
    fdstruct.fd = socket_fd;
    fdstruct.events = POLLIN | POLLOUT;

    int poll_return = poll(&fdstruct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    if (fdstruct.revents & POLLERR)
        print_socket_error(socket_fd);

    ASSERT_FALSE(fdstruct.revents & POLLERR);
    ASSERT_FALSE(fdstruct.revents & POLLHUP);
    ASSERT_FALSE(fdstruct.revents & POLLNVAL);
    ASSERT_FALSE(fdstruct.revents & POLLPRI);

    if (!(fdstruct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fdstruct.revents & POLLOUT);
    
    int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

    int write_return = write(socket_fd, 
                "GET / HTTP/1.1\r\n\r\n", total_write_len);
    int write_errno = errno;

    if (write_return < total_write_len && write_return > 0)
        fprintf(stderr, "Not all of the message was written\n");
    else if (write_return == 0)
        fprintf(stderr, "Unexpected EOF\n");
    else if (write_return < 0)
        print_socket_error(fd);

   ASSERT_EQ(write_return, total_write_len);

    char buf[10000] = {0};
    int total_read_len = 0;
    int curr_read_len = 0;

    curr_read_len = read(fd, buf, 10000);
    EXPECT_EQ(curr_read_len, -1);
    EXPECT_EQ(errno, EAGAIN);

    fdstruct.events = POLLIN;
    poll_return = poll(&fdstruct, 1, 4000);
    ASSERT_EQ(poll_return, 1);

    ASSERT_TRUE(fdstruct.revents & POLLIN);

    curr_read_len = read(fd, &buf[total_read_len], 10000-total_read_len);
    int read_errno = errno;

    EXPECT_EQ(read_errno, 0);
    EXPECT_GT(curr_read_len, 0);

    if (curr_read_len > 0) {
        total_read_len += curr_read_len;
        fprintf(stderr, "Num read: %i\n\n%s\n", total_read_len, buf);
    } else if (curr_read_len == 0) {
        fprintf(stderr, "Unexpected EOF on file descriptor\n");
    } else {
        print_socket_error(fd);
    }
}