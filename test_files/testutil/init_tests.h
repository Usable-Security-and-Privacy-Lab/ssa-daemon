#ifndef SSA_INIT_TESTS_H
#define SSA_INIT_TESTS_H

#include <gtest/gtest.h>
#include <string>

extern "C" {
    #include "suite.h"
}


#define INIT_TESTS(name, daemon_config, server_path)             \
class name : public ::testing::Test {                            \
public:                                                          \
    static void SetUpTestCase() {                                \
        start_daemon(((std::string) daemon_config).c_str(), 1);  \
        if (server_path != NO_SERVER)                            \
            start_server(((std::string) server_path).c_str());   \
    }                                                            \
                                                                 \
    static void TearDownTestCase() {                             \
        cleanup_children();                                      \
    }                                                            \
};

#define INIT_TESTS_NO_VALGRIND(name, daemon_config, server_path) \
class name : public ::testing::Test {                            \
public:                                                          \
    static void SetUpTestCase() {                                \
        start_daemon(((std::string) daemon_config).c_str(), 0);  \
        if (server_path != NO_SERVER)                            \
            start_server(((std::string) server_path).c_str());   \
    }                                                            \
                                                                 \
    static void TearDownTestCase() {                             \
        cleanup_children();                                      \
    }                                                            \
};


#endif