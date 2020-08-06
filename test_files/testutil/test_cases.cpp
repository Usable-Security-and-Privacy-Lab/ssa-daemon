#include <gtest/gtest.h>

#include "socket_wrappers.h"
#include "test_cases.h"
#include "timeouts.h"



void run_connect_test(enum test_s status, int error_code) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);
    
    if (status == TEST_S_FAIL_CONNECT)
        connect_to_localhost_fail(fd, error_code);
    else
        connect_to_localhost(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
    return;
}


void run_version_test(int tls_version, enum test_s status) {

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, LOCALHOST);

    /* TODO: add TLS version setsockopt to helper_functions.c/h */
}

void run_session_test(enum test_s status);
void run_session_version_test(int tls_version, enum test_s status);