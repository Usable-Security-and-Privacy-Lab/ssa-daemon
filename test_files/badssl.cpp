#include <gtest/gtest.h>

#include <future>
#include <stdlib.h>
#include <string>

extern "C" { // To indicate that the code is C code when linking--important
#include "helper_functions.h"
}

using namespace std;

#define TEST_TIMEOUT_BEGIN  std::promise<bool> promisedFinished; \
                            auto futureResult = promisedFinished.get_future(); \
                            std::thread([&](std::promise<bool>& finished) {

/// X is in milliseconds
#define TEST_TIMEOUT_FAIL_END(X)  finished.set_value(true); \
                                  }, std::ref(promisedFinished)).detach(); \
                                  bool testTimedOut = futureResult.wait_for(std::chrono::milliseconds(X)) == std::future_status::timeout; \
                                  EXPECT_FALSE(testTimedOut);

#define TEST_TIMEOUT_SUCCESS_END(X) finished.set_value(true); \
                                    }, std::ref(promisedFinished)).detach(); \
                                    bool testTimedOut = futureResult.wait_for(std::chrono::milliseconds(X)) == std::future_status::timeout; \
                                    EXPECT_TRUE(testTimedOut);

// Each connection should DEFINITELY take less than 4 seconds to run
#define TIMEOUT 4000 


// We use strings because compiler throws errors with defined strings into char*s
// These URLs should all fail on a secure connection
const string EXPIRED_URL = "expired.badssl.com";
const string WRONG_HOST_URL = "wrong.host.badssl.com";
const string SELF_SIGNED_URL = "self-signed.badssl.com";
const string UNTRUSTED_ROOT_URL = "untrusted-root.badssl.com";
const string REVOKED_URL = "revoked.badssl.com";
const string PINNING_URL_BAD = "pinning-test.badssl.com";
const string SHA1_INTERMEDIATE_URL = "sha1-intermediate.badssl.com";
const string TLS1_0_URL = "tls-v1-0.badssl.com";
const string TLS1_1_URL = "tls-v1-1.badssl.com";
// TODO: More to be added...

const string HTTP_URL = "http.badssl.com";

// These URLs may fail or pass, but would be best to fail

// These URLs may fail or pass, but would be best to pass
const string PARTIAL_CHAIN_URL = "incomplete-chain.badssl.com";
const string NO_COMMON_NAME_URL = "no-common-name.badssl.com";
const string NO_SUBJECT_URL = "no-subject.badssl.com";

// These URLs should pass on a secure connection
const string REGULAR_URL = "badssl.com";
const string SHA256_URL = "sha256.badssl.com";
const string SHA384_URL = "sha384.badssl.com";
const string SHA512_URL = "sha512.badssl.com";
const string TLS1_2_URL = "tls-v1-2.badssl.com";


const string HTTPS_PORT = "443";
const string HTTP_PORT = "443";
const string TLS1_0_PORT = "1010";
const string TLS1_1_PORT = "1011";
const string TLS1_2_PORT = "1012";


class BadSSLTests : public testing::Test {

public:
    char *resp;
    int resp_len;
    int result;

    virtual void SetUp() {
        resp = NULL;
        resp_len = 0;
        result = 0;
    }

    virtual void TearDown() { }
};

/*******************************************************************************
 *                TESTS THAT SHOULD NOT CONNECT SUCCESSFULLY
 ******************************************************************************/

// TODO: in the future, test the error strings as well

TEST_F(BadSSLTests, Expired) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(EXPIRED_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT); // ERROR STATE
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, WrongHost) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WRONG_HOST_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, SelfSigned) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SELF_SIGNED_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, UntrustedRoot) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(UNTRUSTED_ROOT_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, Revoked) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(REVOKED_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}


TEST_F(BadSSLTests, Sha1IntermediateCert) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SHA1_INTERMEDIATE_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, TLSVersion1_0) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TLS1_0_URL.c_str(), TLS1_0_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, TLSVersion1_1) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TLS1_1_URL.c_str(), TLS1_1_PORT.c_str(), &resp, &resp_len);
    EXPECT_EQ(result, (int) E_CONNECT);
    EXPECT_EQ(errno, EPROTO);
    
    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}


/*******************************************************************************
 *                    TESTS THAT SHOULD CONNECT SUCCESSFULLY
 ******************************************************************************/


TEST_F(BadSSLTests, RegularWebsite) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(REGULAR_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);

    ASSERT_EQ(result, 0); // PASS STATE
    ASSERT_GT(resp_len, 0);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, Sha256Certificate) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SHA256_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);

    ASSERT_EQ(result, 0); // PASS STATE
    ASSERT_GT(resp_len, 0);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, Sha384Certificate) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SHA384_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);

    ASSERT_EQ(result, 0); // PASS STATE
    ASSERT_GT(resp_len, 0);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, Sha512Certificate) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SHA512_URL.c_str(), HTTPS_PORT.c_str(), &resp, &resp_len);

    ASSERT_EQ(result, 0); // PASS STATE
    ASSERT_GT(resp_len, 0);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(BadSSLTests, TLSVersion1_2) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TLS1_2_URL.c_str(), TLS1_2_PORT.c_str(), &resp, &resp_len);

    ASSERT_EQ(result, 0); // PASS STATE
    ASSERT_GT(resp_len, 0);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}





