#ifndef SSA_TEST_CASES_H
#define SSA_TEST_CASES_H

#include <string>


enum test_s {
    TEST_S_SUCCEED = 0,
    TEST_S_FAIL_CONNECT,
    TEST_S_FAIL_SETSOCKOPT,
    TEST_S_FAIL_GETSOCKOPT,
};

void run_connect_test(enum test_s status, int e_code);
void run_version_test(int tls_version, enum test_s status, int e_code);

void run_session_test(enum test_s status, int e_code);
void run_session_version_test(int tls_version, enum test_s status, int e_code);



#define CONNECT_TEST(test_suite, status, error_code)                           \
    TEST(test_suite, ConnectTest) {                                            \
        run_connect_test(status, error_code);                                  \
    }

#define TLS1_3_CONNECT_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_3ConnectTest) {                                      \
        run_version_test(3, status, error_code);                               \
    }

#define TLS1_2_CONNECT_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_2ConnectTest) {                                      \
        run_version_test(2, status, error_code);                               \
    }

#define TLS1_1_CONNECT_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_1ConnectTest) {                                      \
        run_version_test(1, status, error_code);                               \
    }

#define TLS1_0_CONNECT_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_0ConnectTest) {                                      \
        run_version_test(0, status, error_code);                               \
    }



#define SESSION_TEST(test_suite, status, error_code)                           \
    TEST(test_suite, SessionTest) {                                            \
        run_session_test(status, error_code);                                  \
    }

#define TLS1_3_SESSION_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_3SessionTest) {                                      \
        run_session_version_test(3, status, error_code);                       \
    }

#define TLS1_2_SESSION_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_2SessionTest) {                                      \
        run_session_version_test(2, status, error_code);                       \
    }

#define TLS1_1_SESSION_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_1SessionTest) {                                      \
        run_session_version_test(1, status, error_code);                       \
    }

#define TLS1_0_SESSION_TEST(test_suite, status, error_code)                    \
    TEST(test_suite, TLS1_0SessionTest) {                                      \
        run_session_version_test(0, status, error_code);                       \
    }



#endif