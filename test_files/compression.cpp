#include <gtest/gtest.h>

#include "helper_functions.h"
#include "timeouts.h"



TEST(CompressionTests, CompressionEnabled) {

    bool compression_used = false;
    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    enable_compression(fd, SHOULD_SUCCEED);

    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);

    get_compression(fd, SHOULD_SUCCEED, &compression_used);

    ASSERT_TRUE(compression_used);
}

TEST(CompressionTests, CompressionDisabled) {

    bool compression_used = true;
    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    disable_compression(fd, SHOULD_SUCCEED);

    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);

    get_compression(fd, SHOULD_SUCCEED, &compression_used);

    ASSERT_FALSE(compression_used);
}

