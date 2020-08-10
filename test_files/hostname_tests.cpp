#include <gtest/gtest.h>

#include "helper_functions.h"
#include "timeouts.h"

/*******************************************************************************
 *                              TEST CASES
 ******************************************************************************/

#define INCORRECT_HOSTNAME "localhostlocalhost"
#define MESSENGER_HOSTNAME "messenger.com"

TEST(HostnameTests, SetHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    set_hostname(fd, LOCALHOST);
    connect_to_host(fd, LOCALHOST, LOCAL_PORT);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}


TEST(HostnameTests, GetHostname) {

    TEST_TIMEOUT_BEGIN

    std::string hostname;

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    set_hostname(fd, LOCALHOST);
    get_hostname(fd, &hostname);

    if (hostname.compare(LOCALHOST) != 0) {
        fprintf(stderr,
                "Set hostname doesn't match retrieved hostname\n Set hostname: %s\n Retrieved hostname: %s\n",
                LOCALHOST, hostname);
        FAIL();
    }

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT);
}



TEST(HostnameTests, GetUnsetHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    get_hostname_fail(fd, EINVAL); /* TODO: change errno */

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT);
}



TEST(HostnameTests, SetHostnameAfterConnect) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();
    
    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);
    set_hostname_fail(fd, INCORRECT_HOSTNAME, EOPNOTSUPP);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}


TEST(HostnameTests, WrongHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    set_hostname(fd, INCORRECT_HOSTNAME);
    connect_to_localhost_fail(fd, EPROTO);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}



TEST(HostnameTests, SubjectAltHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    set_hostname(fd, MESSENGER_HOSTNAME);
    connect_to_host(fd, MESSENGER_HOSTNAME, HTTPS_PORT);
    /* messenger.com is a subject alt name of the facebook.com cert */

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}



TEST(HostnameTests, NoHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    connect_to_localhost_fail(fd, EPROTO);
    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}



TEST(HostnameTests, ChangeHostname) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0) 
        FAIL();
    
    set_hostname(fd, INCORRECT_HOSTNAME);
    set_hostname(fd, LOCALHOST);
    connect_to_localhost(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_SHORT)
}