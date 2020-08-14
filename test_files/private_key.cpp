#include <gtest/gtest.h>

#include "testutil/timeouts.h"
#include "testutil/init_tests.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include "../in_tls.h"

}

INIT_TESTS(PrivateKeyTests, "configs/default_localhost.yml", NULL)

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


/*****************************************************
 *                  Private Key Testing              *
 * **************************************************/



TEST(PrivateKeyTests, SetCorrectKey) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, 
                "certs/testing/rsa_key.pem", strlen("certs/testing/rsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, SetCorrectECDSAKey) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/ecdsa", strlen("certs/testing/ecdsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, 
                "certs/testing/ecdsa_key.pem", strlen("certs/testing/ecdsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, SetWrongKeyPath) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/server_chain.pem", strlen("certs/server_chain.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, 
                "fake/path/key.pem", strlen("fake/path/key.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EBADF);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, CertKeyMismatch) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/dsa_key.pem", strlen("certs/testing/dsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EPROTO);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, ECDSAKeyMismatch) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/ecdsa_key.pem", strlen("certs/testing/ecdsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EPROTO);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, LoadTwoKeysCorrect) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/rsa_key.pem", strlen("certs/testing/rsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/dsa", strlen("certs/testing/dsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/dsa_key.pem", strlen("certs/testing/dsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);    

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, LoadTwoChainsOneKey) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/dsa", strlen("certs/testing/dsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/rsa_key.pem", strlen("certs/testing/rsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);    

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, SetKeyWithoutChain) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, 
                "certs/testing/ecdsa_key.pem", strlen("certs/testing/ecdsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EPROTO);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, LoadTwoChainsBeforeKeys) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/ecdsa", strlen("certs/testing/ecdsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);    
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/rsa_key.pem", strlen("certs/testing/rsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/ecdsa_key.pem", strlen("certs/testing/ecdsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(PrivateKeyTests, OneCorrectKeyOfTwo) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/ecdsa", strlen("certs/testing/ecdsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);    
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/dsa_key.pem", strlen("certs/testing/dsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EPROTO);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY,
                "certs/testing/ecdsa_key.pem", strlen("certs/testing/ecdsa_key.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        print_socket_error(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}