#include <gtest/gtest.h>

#include <stdlib.h>

// Go to https://github.com/google/googletest/blob/master/googletest/docs/primer.md
// for a more thorough explanation of concepts


// TO COMPILE GOOGLETEST TESTS:
// g++ -o <test-name> <your_test_files.cpp> <your_headers.h> -lgtest_main -lgtest -pthread

// Tests like this implicitly create a class; you don't need to
TEST(SimpleTests, FirstTest) {
    ASSERT_EQ(4, 2 + 2); // Assert aborts on failure

}

TEST(SimpleTests, SecondTest) {
    EXPECT_EQ(5+5, 10);
    ASSERT_EQ(3+3, 6);
    // EXPECT reports errors but does not abort on failure.
    // It is useful for non-fatal errors
}

TEST(SimpleTests, MallocTest) {
    char *ptr = (char*) malloc(sizeof(char));
    ASSERT_NE(ptr, nullptr); 
    // ASSERT_NE expects two items to be not equal.
    // When asserting pointers, ALWAYS use nullptr instead of NULL
}

/*
TEST(SimpleTests, StringTest) {
    char *str1 = "hello world!";
    char *str2 = "HELLO WORLD!";

    EXPECT_STRNE(str1, str2); // C string comparisons are available
    EXPECT_STRCASEEQ(str1, str2); // Use STRCASE (EQ or NE) to ignore case
    // Note: a null pointer and an empty string are considered different.
}
*/

// If you want multiple test cases that have common data, use a class

class GroupTest : public testing::Test
{
public:
    int sharedInt;

    virtual void SetUp() {
        sharedInt = 5;

    }

    virtual void TearDown() {
    
    }
};
// The tests aren't put inside the class, but they DO use its members.

// Note that we use TEST_F instead of TEST
// This indicates that the class surrounding the test is declared
// by us, so they don't have to build one.
TEST_F(GroupTest, firstGroupTest) {
    EXPECT_EQ(sharedInt, 5);
    sharedInt = 10;
}

// SetUp() runs before every test case, so variables within it are reset
TEST_F(GroupTest, secondGroupTest) {
    EXPECT_NE(sharedInt, 10);
}


// Gtest does not have built in support for timed tests; but
// there is a simple macro to do so:

#include <future>

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

// No, I don't know how the internals of these work.

//Example: This test should fail after 2000 miliseconds (or 2 seconds)
TEST(TimedTest, FirstTimedTest) {
    TEST_TIMEOUT_BEGIN

    sleep(10);

    TEST_TIMEOUT_FAIL_END(2000)
}

// You can even nest these macros safely (if you want specifics on how long the
// test takes cumulatively). It's generally cleaner to use them sequentially though.
TEST(TimedTest, SecondTimedTest) {
    TEST_TIMEOUT_BEGIN

    TEST_TIMEOUT_BEGIN

    sleep(1);

    TEST_TIMEOUT_FAIL_END(2000)

    sleep(2);

    TEST_TIMEOUT_FAIL_END(2500)
}