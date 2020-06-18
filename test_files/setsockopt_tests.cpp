#include <gtest/gtest.h>

#include "timeouts.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include "../in_tls.h"


}



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


TEST(SetsockoptTests, SetHostnameCorrect) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, 
                "google.com", strlen("google.comm"));

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}



TEST(SetsockoptTests, SetHostnameNull) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_NE(fd, -1);
    
    int ret = setsockopt(fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, 
                NULL, 0);

    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EINVAL);

    if (ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

