#include <gtest/gtest.h>

#include "testutil/socket_wrappers.h"
#include "testutil/init_tests.h"
#include "testutil/timeouts.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include "../in_tls.h"

}

INIT_TESTS(SocketAPITests, "configs/default_localhost.yml", "servers/regular")

TEST_F(SocketAPITests, SocketCreation) {

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();
    close(fd);
}

TEST_F(SocketAPITests, SocketWrongDomain) {

    int fd = socket(AF_NETLINK, 0, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd >= 0) {
        fprintf(stderr, "Socket creation succeeded despite bad domain\n");
        close(fd);
        FAIL();
    }

    if (socket_errno != ESOCKTNOSUPPORT) {
        fprintf(stderr, "Errno was %i: %s. Expected errno was %i: %s\n",
                socket_errno, strerror(socket_errno), 
                ESOCKTNOSUPPORT, strerror(ESOCKTNOSUPPORT));
        FAIL();
    }
}

TEST_F(SocketAPITests, SocketWrongType) {
    /* TODO: someday we'll implement DTLS. this should be changed then */

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd >= 0) {
        fprintf(stderr, "Socket creation succeeded despite bad type\n");
        close(fd);
        FAIL();
    }

    if (socket_errno != EPROTONOSUPPORT) {
        fprintf(stderr, "Errno was %i: %s. Expected errno was %i: %s\n",
                socket_errno, strerror(socket_errno), 
                EPROTONOSUPPORT, strerror(EPROTONOSUPPORT));
        FAIL();
    }
}

TEST_F(SocketAPITests, SocketWithNonblockType) {

    int fd = create_socket(NONBLOCKING_SOCKET); 
    if (fd < 0)
        FAIL();
    
    close(fd);
}

TEST_F(SocketAPITests, ConnectWithNonblockSocket) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(NONBLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);
    connect_to_localhost_fail(fd, EINPROGRESS);   
    
    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}


TEST_F(SocketAPITests, DoubleConnectFail) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);

    connect_to_localhost(fd);
    connect_to_localhost_fail(fd, EISCONN);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

TEST_F(SocketAPITests, ConnectThenListenFail) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);

    connect_to_localhost(fd);

    int ret = listen(fd, SOMAXCONN);
    if (ret == 0) {
        fprintf(stderr, "listen() succeeded on connect()ed socket.\n");
        ADD_FAILURE();
    }
    
    if (errno != EOPNOTSUPP) {
        fprintf(stderr, "Errno was %i: %s. Expected errno was %i: %s\n",
                errno, strerror(errno), 
                EOPNOTSUPP, strerror(EOPNOTSUPP));
        ADD_FAILURE();
    }

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}



TEST_F(SocketAPITests, ConnectThenBindFail) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);

    connect_to_localhost(fd);
    
    struct sockaddr_in int_addr = {0};
    
    int_addr.sin_family = AF_INET;
    int_addr.sin_port = 0;
    int_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
 
    int ret = bind(fd, (struct sockaddr*) &int_addr, sizeof(sockaddr_in));

    if (ret == 0) {
        fprintf(stderr, "bind() after connect() succeeded (it shouldn\'t)\n");
        ADD_FAILURE();
    }

    if (errno != EINVAL) {
        fprintf(stderr, "Errno was %i: %s. Expected errno was %i: %s\n",
                errno, strerror(errno), 
                EINVAL, strerror(EINVAL));
        ADD_FAILURE();
    }

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}
/*

TEST_F(SocketAPITests, ConnectThenAcceptFail) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);

    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);

    struct sockaddr temp_addr;
    socklen_t temp_addrlen;
    int ret = accept(fd, &temp_addr, &temp_addrlen);

    if (ret != -1) {
        fprintf(stderr, "accept() after connect() succeeded (it shouldn\'t)\n");
        ADD_FAILURE();
    }

    if (errno != EINVAL) {
        fprintf(stderr, "Errno was %i: %s. Expected errno was %i: %s\n",
                errno, strerror(errno), 
                EINVAL, strerror(EINVAL));
        ADD_FAILURE();
    }

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}
*/