#include <gtest/gtest.h>

#include "testutil/socket_wrappers.h"
#include "testutil/init_tests.h"
#include "testutil/timeouts.h"


void do_connection_test(std::string hostname, 
        std::string port, bool should_connect) {

    TEST_TIMEOUT_BEGIN

    int fd = create_socket(BLOCKING_SOCKET);
    if (fd < 0)
        FAIL();

    set_hostname(fd, hostname);

    if (should_connect)
        connect_to_host(fd, hostname, port);
    else
        connect_to_host_fail(fd, hostname, port, EPROTO);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

#define TEST_CONNECT_FAIL(testname, hostname, port)                 \
    TEST_F(BadSSLTests, testname) {                                 \
        do_connection_test(hostname, port, SHOULD_FAIL);            \
    }


#define TEST_CONNECT_PASS(testname, hostname, port)                 \
    TEST_F(BadSSLTests, testname) {                                 \
        do_connection_test(hostname, port, SHOULD_SUCCEED);         \
    }





INIT_TESTS(BadSSLTests, "configs/default.yml", "servers/regular")


/*******************************************************************************
 *                TESTS THAT SHOULD NOT CONNECT SUCCESSFULLY
 ******************************************************************************/

TEST_CONNECT_FAIL(Expired, "expired.badssl.com", "443")
TEST_CONNECT_FAIL(WrongHost, "wrong.host.badssl.com", "443")
TEST_CONNECT_FAIL(SelfSigned, "self-signed.badssl.com", "443")
TEST_CONNECT_FAIL(UntrustedRoot, "untrusted-root.badssl.com", "443")
TEST_CONNECT_FAIL(Revoked, "revoked.badssl.com", "443")
TEST_CONNECT_FAIL(Sha1IntermediateCert, "sha1-intermediate.badssl.com", "443")
TEST_CONNECT_FAIL(TLSVersion1_0, "tls-v1-0.badssl.com", "1010")
TEST_CONNECT_FAIL(TLSVersion1_1, "tls-v1-1.badssl.com", "1011")
TEST_CONNECT_FAIL(NoCommonName, "no-common-name.badssl.com", "443")
TEST_CONNECT_FAIL(HttpUrl, "http.badssl.com", "80")
TEST_CONNECT_FAIL(CipherRC4MD5, "rc4-md5.badssl.com", "443")
TEST_CONNECT_FAIL(CipherRC4, "rc4.badssl.com", "443")
TEST_CONNECT_FAIL(Cipher3DES, "3des.badssl.com", "443")
TEST_CONNECT_FAIL(CipherNull, "null.badssl.com", "443")
TEST_CONNECT_FAIL(KeyDH480, "dh480.badssl.com", "443")
TEST_CONNECT_FAIL(KeyDH512, "dh512.badssl.com", "443")
TEST_CONNECT_FAIL(KeyDH2048, "dh2048.badssl.com", "443")
TEST_CONNECT_FAIL(KeyDHSmallParams, "dh-small-subgroup.badssl.com", "443")
TEST_CONNECT_FAIL(KeyDHComposite, "dh-composite.badssl.com", "443")
TEST_CONNECT_FAIL(StaticRSA, "static-rsa.badssl.com", "443")
TEST_CONNECT_FAIL(Superfish, "superfish.badssl.com", "443")
TEST_CONNECT_FAIL(EDellRoot, "edellroot.badssl.com", "443")
TEST_CONNECT_FAIL(DSDTestProvider, "dsdtestprovider.badssl.com", "443")



// These URLs may fail or pass, but would be best to fail
TEST_CONNECT_FAIL(IncompleteChain, "incomplete-chain.badssl.com", "443")
TEST_CONNECT_FAIL(NoSubject, "no-subject.badssl.com", "443")



/*******************************************************************************
 *                    TESTS THAT SHOULD CONNECT SUCCESSFULLY
 ******************************************************************************/


TEST_CONNECT_PASS(RegularWebsite, "badssl.com", "443")
TEST_CONNECT_PASS(Sha256Certificate, "sha256.badssl.com", "443")
TEST_CONNECT_PASS(Sha384Certificate, "sha384.badssl.com", "443")
TEST_CONNECT_PASS(Sha512Certificate, "sha512.badssl.com", "443")
TEST_CONNECT_PASS(TLSVersion1_2, "tls-v1-2.badssl.com", "443")
TEST_CONNECT_PASS(SubjectAltNames1000, "1000-sans.badssl.com", "443")
TEST_CONNECT_PASS(ElipticCurve256, "ecc256.badssl.com", "443")
TEST_CONNECT_PASS(ElipticCurve384, "ecc384.badssl.com", "443")
TEST_CONNECT_PASS(RSA2048, "rsa2048.badssl.com", "443")
TEST_CONNECT_PASS(RSA4096, "rsa4096.badssl.com", "443")
TEST_CONNECT_PASS(RSA8192, "rsa8192.badssl.com", "443")
TEST_CONNECT_PASS(ExtendedValidation, "extended-validation.badssl.com", "443")
TEST_CONNECT_PASS(LongSubdomainWithDashes, "long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com", "443")
TEST_CONNECT_PASS(LongSubdomainWithoutDashes, "longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com", "443")

