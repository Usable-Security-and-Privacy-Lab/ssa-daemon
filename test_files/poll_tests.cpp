#include <gtest/gtest.h>

#include "testutil/socket_wrappers.h"
#include "testutil/init_tests.h"
#include "testutil/timeouts.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <stdio.h>
#include <unistd.h>
#include "../in_tls.h"

}

#define HOSTNAME "google.com"
#define MAX_FDS 10


INIT_TESTS(AsyncTests, "configs/default.yml", NULL)



TEST_F(AsyncTests, Connect1) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(NONBLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, HOSTNAME);
    connect_to_host_fail(fd, HOSTNAME, HTTPS_PORT, EINPROGRESS);
    
    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = 0;
    fd_struct.revents = 0;

    errno = 0;
    int poll_return = poll(&fd_struct, 1, -1);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_GT(poll_return, 0);

    EXPECT_FALSE(fd_struct.revents & POLLERR);
    EXPECT_FALSE(fd_struct.revents & POLLHUP);
    EXPECT_FALSE(fd_struct.revents & POLLNVAL);
    EXPECT_FALSE(fd_struct.revents & POLLPRI);
    if (fd_struct.revents & POLLERR)
        print_socket_error(fd, "POLLERR");

    if (!(fd_struct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fd_struct.revents & POLLOUT);

    connect_to_host_fail(fd, HOSTNAME, HTTPS_PORT, EISCONN);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}


TEST_F(AsyncTests, ConnectTimeout1) {

    int fd = create_socket(NONBLOCKING_SOCKET); 
    if (fd < 0)
        FAIL();

    set_hostname(fd, HOSTNAME);
    connect_to_host(fd, HOSTNAME, HTTPS_PORT);

    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = POLLIN | POLLOUT | POLLERR | POLLPRI | POLLHUP;

    int poll_return = poll(&fd_struct, 1, 20);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 0);

    close(fd);
}


TEST_F(AsyncTests, ConnectWriteRead1) {

    int fd = create_socket(NONBLOCKING_SOCKET); 
    if (fd < 0)
        FAIL();

    set_hostname(fd, HOSTNAME);
    connect_to_host(fd, HOSTNAME, HTTPS_PORT);

    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = POLLIN | POLLOUT;

    int poll_return = poll(&fd_struct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    ASSERT_FALSE(fd_struct.revents & POLLERR);
    ASSERT_FALSE(fd_struct.revents & POLLHUP);
    ASSERT_FALSE(fd_struct.revents & POLLNVAL);
    ASSERT_FALSE(fd_struct.revents & POLLPRI);

    if (!(fd_struct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fd_struct.revents & POLLOUT);

    int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

    int write_return = write(fd,
        "GET / HTTP/1.1\r\n\r\n", total_write_len);
    int write_errno = errno;

    if (write_return < total_write_len && write_return > 0)
        fprintf(stderr, "Not all of the message was written\n");
    else if (write_return == 0)
        fprintf(stderr, "Unexpected EOF\n");
    else if (write_return < 0)
        print_socket_error(fd, "write()");

    EXPECT_EQ(write_errno, 0);
    ASSERT_EQ(write_return, total_write_len);

    char buf[10000] = {0};
    int total_read_len = 0;
    int curr_read_len;

    curr_read_len = read(fd, buf, 10000);
    EXPECT_EQ(curr_read_len, -1);
    EXPECT_EQ(errno, EAGAIN);

    fd_struct.events = POLLIN;
    poll_return = poll(&fd_struct, 1, 4000);
    ASSERT_EQ(poll_return, 1);

    ASSERT_TRUE(fd_struct.revents & POLLIN);

    curr_read_len = read(fd, &buf[total_read_len], 10000-total_read_len);
    int read_errno = errno;

    if (curr_read_len == 0) {
        fprintf(stderr, "Unexpected EOF on file descriptor\n");
    } else if (curr_read_len < 0){
        print_socket_error(fd, "read()");
    }

    EXPECT_EQ(read_errno, 0);
    ASSERT_GT(curr_read_len, 0);

    close(fd);
    fd = -1;
}

TEST_F(AsyncTests, Connect5) {

    const int FD_COUNT = 5;
    int fds[FD_COUNT] = {-1};
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = create_socket(NONBLOCKING_SOCKET); 
        if (fds[i] < 0)
            FAIL();

        set_hostname(fds[i], HOSTNAME);
        connect_to_host_fail(fds[i], HOSTNAME, HTTPS_PORT, EINPROGRESS);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left_to_connect = FD_COUNT;
    while(fds_left_to_connect > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            if (fd_structs[i].revents == 0)
                continue;

            num_fds_ready++;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            if (!(fd_structs[i].revents & POLLOUT)) {
                fprintf(stderr, "Socket wasn't ready for writing\n");
                continue;
            }

            ASSERT_TRUE(fd_structs[i].revents & POLLOUT);

            connect_to_host_fail(fds[i], HOSTNAME, HTTPS_PORT, EISCONN);
            fd_structs[i].events = 0;
        }

        ASSERT_EQ(num_fds_ready, poll_return);

        fds_left_to_connect -= num_fds_ready;
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(AsyncTests, Connect23) {

    const int FD_COUNT = 23;
    int fds[FD_COUNT] = {-1};
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = create_socket(NONBLOCKING_SOCKET); 
        if (fds[i] < 0)
            FAIL();

        set_hostname(fds[i], HOSTNAME);
        connect_to_host(fds[i], HOSTNAME, HTTPS_PORT);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left_to_connect = FD_COUNT;
    while(fds_left_to_connect > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            if (fd_structs[i].revents == 0)
                continue;

            num_fds_ready++;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            if (!(fd_structs[i].revents & POLLOUT)) {
                fprintf(stderr, "Socket wasn't ready for writing\n");
                continue;
            }

            ASSERT_TRUE(fd_structs[i].revents & POLLOUT);
            
            connect_to_host_fail(fds[i], HOSTNAME, HTTPS_PORT, EISCONN);

            fd_structs[i].events = 0;
        }

        ASSERT_EQ(num_fds_ready, poll_return);

        fds_left_to_connect -= num_fds_ready;
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(AsyncTests, ConnectWriteRead5) {

    const int FD_COUNT = 5;
    int fds[FD_COUNT] = {-1};
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = create_socket(NONBLOCKING_SOCKET); 
        if (fds[i] < 0)
            FAIL();

        set_hostname(fds[i], HOSTNAME);
        connect_to_host(fds[i], HOSTNAME, HTTPS_PORT);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left = FD_COUNT;
    while(fds_left > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0);
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            char buf[10000] = {0};
            int curr_read_len;

            if (fd_structs[i].revents == 0)
                continue;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            num_fds_ready++;

            if (fd_structs[i].revents & POLLOUT) { /* ready for write */
                connect_to_host_fail(fds[i], HOSTNAME, HTTPS_PORT, EISCONN);


                int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

                int write_return = write(fds[i],
                    "GET / HTTP/1.1\r\n\r\n", total_write_len);
                int write_errno = errno;

                if (write_return < total_write_len && write_return > 0)
                    fprintf(stderr, "Not all of the message was written\n");
                else if (write_return == 0)
                    fprintf(stderr, "Unexpected EOF\n");

                EXPECT_EQ(write_errno, 0);
                ASSERT_EQ(write_return, total_write_len);

                fd_structs[i].events = POLLIN | POLLHUP | POLLERR;

            } else if (fd_structs[i].revents & POLLIN) { /* ready for read */
                curr_read_len = read(fds[i], buf, 10000);
                int read_errno = errno;

                if (curr_read_len == 0) {
                    fprintf(stderr, "Unexpected EOF on file descriptor\n");
                } else if (curr_read_len < 0){
                    print_socket_error(fds[i], "read()");
                }

                EXPECT_EQ(read_errno, 0);
                ASSERT_GT(curr_read_len, 0);

                fd_structs[i].events = 0;

                fds_left -= 1;

            }
        }

        ASSERT_EQ(num_fds_ready, poll_return);
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}
