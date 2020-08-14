#include <gtest/gtest.h>

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



#define TIMEOUT_SHORT 5000
#define TIMEOUT_LONG 10000
#define TIMEOUT_VERY_LONG 30000

