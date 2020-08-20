#include <gtest/gtest.h>

#include "testutil/timeouts.h"
#include "testutil/init_tests.h"
#include "testutil/socket_wrappers.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include "../in_tls.h"

}

// INIT_TESTS(ServerChainTests, "configs/default_localhost.yml", "servers/regular")

// TEST_F(ServerChainTests, SocketCreation) {

//     int fd = create_socket(BLOCKING_SOCKET);
//     if (fd < 0)
//         FAIL();
//     close(fd);
// }

INIT_TESTS(ServerChainTests, "configs/server_chain.yml", NULL)

TEST(ServerChainTests, SetCertFileCorrect) {

    // TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();
    
    ASSERT_GE(fd, 0);
    
    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, 
                "certs/server_chain.pem", strlen("certs/server_chain.pem")+1);

    EXPECT_EQ(setsockopt_ret, 0);

    if (setsockopt_ret < 0)
        FAIL();

    close(fd);

    // TEST_TIMEOUT_FAIL_END(TIMEOUT_VERY_LONG)
}