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