/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

INIT_TESTS(ServerChainTests, "configs/server_chain.yml", NULL)

TEST(ServerChainTests, SetCertFileCorrect) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/server_chain.pem", strlen("certs/server_chain.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetCertDirectoryCorrect) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetTwoCorrectChains) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/server_chain.pem", strlen("certs/server_chain.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetThreeCorrectChains) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/ecdsa", strlen("certs/testing/ecdsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();
    
    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/server_chain.pem", strlen("certs/server_chain.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetOneWrongChain) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/rsa", strlen("certs/testing/rsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/wrong/path", strlen("certs/wrong/path")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EINVAL);

    setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/testing/ecdsa", strlen("certs/testing/ecdsa")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetWrongCertPath) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "fake/path/cert.pem", strlen("fake/path/cert.pem")+1);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EINVAL);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

TEST(ServerChainTests, SetNullCertPath) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0) 
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                NULL, 0);

    EXPECT_EQ(setsockopt_ret, -1);
    EXPECT_EQ(errno, EINVAL);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}

