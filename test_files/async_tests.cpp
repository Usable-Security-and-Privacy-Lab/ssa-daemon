#include <gtest/gtest.h>

#include "helper_functions.h"
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


#define HOSTNAME "www.yahoo.com"

TEST(AsyncTests, PollSocketConnect) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, HOSTNAME);
    connect_to_host_fail(fd, HOSTNAME, HTTPS_PORT, EINPROGRESS);

    struct pollfd fdstruct = {0};
    fdstruct.fd = fd;
    fdstruct.events = POLLIN | POLLOUT | POLLERR | POLLPRI | POLLHUP;

    int poll_return = poll(&fdstruct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    if (fdstruct.revents & POLLERR)
        print_socket_error(fd, "poll() revents POLERR");

    ASSERT_FALSE(fdstruct.revents & POLLERR);
    ASSERT_FALSE(fdstruct.revents & POLLHUP);
    ASSERT_FALSE(fdstruct.revents & POLLNVAL);
    ASSERT_FALSE(fdstruct.revents & POLLPRI);

    if (!(fdstruct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fdstruct.revents & POLLIN);
    ASSERT_TRUE(fdstruct.revents & POLLOUT);

    connect_to_host(fd, HOSTNAME, HTTPS_PORT);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}


TEST(AsyncTests, PollSocketConnectRead) {

    TEST_TIMEOUT_BEGIN

    int socket_fd = create_socket(NONBLOCKING_SOCKET);
    if (socket_fd < 0)
        FAIL();

    set_hostname(socket_fd, HOSTNAME);
    connect_to_host_fail(socket_fd, HOSTNAME, HTTPS_PORT, EINPROGRESS);

    struct pollfd fdstruct = {0};
    fdstruct.fd = socket_fd;
    fdstruct.events = POLLIN | POLLOUT;

    int poll_return = poll(&fdstruct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    if (fdstruct.revents & POLLERR)
        print_socket_error(socket_fd, "poll() revents POLLERR");

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
        print_socket_error(socket_fd, "write()");

   ASSERT_EQ(write_return, total_write_len);

    char buf[10000] = {0};
    int total_read_len = 0;
    int curr_read_len = 0;

    curr_read_len = read(socket_fd, buf, 10000);
    EXPECT_EQ(curr_read_len, -1);
    EXPECT_EQ(errno, EAGAIN);

    fdstruct.events = POLLIN;
    poll_return = poll(&fdstruct, 1, 4000);
    ASSERT_EQ(poll_return, 1);

    ASSERT_TRUE(fdstruct.revents & POLLIN);

    curr_read_len = read(socket_fd, &buf[total_read_len], 10000-total_read_len);
    int read_errno = errno;

    EXPECT_EQ(read_errno, 0);
    EXPECT_GT(curr_read_len, 0);

    if (curr_read_len > 0) {
        total_read_len += curr_read_len;
        fprintf(stderr, "Num read: %i\n\n%s\n", total_read_len, buf);
    } else if (curr_read_len == 0) {
        fprintf(stderr, "Unexpected EOF on file descriptor\n");
    } else {
        print_socket_error(socket_fd, "read()");
    }

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}