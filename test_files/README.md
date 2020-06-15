# Testing Documentation

## Purpose
The purpose of this documentation is to outline how to build, run, and add to the tests developed for the SSA daemon. Testing is an important part of any project, and even more so for projects that are meant to run for unspecified amounts of time in the background (such as daemons) or projects that handle security measures (such as TLS). As such, comprehensive tests should be run after each addition to the SSA Daemon to ensure that no errors are introduced into the system. This guide will walk through the testing framework that is in place for the project, and give instruction on adding tests to the framework.

The testing library currently in use for the Daemon is GoogleTest. While basic information is given on the GoogleTest library here, readers should refer to [the GoogleTest documentation](https://github.com/google/googletest/blob/master/googletest/docs/primer.md) for a more complete guide.


## Prerequisites

Follow the instructions to install the SSA kernel module and SSA Daemon. Have the SSA daemon running on your computer (preferrably with Valgrind) before running any of the test suites. To run the Daemon using Valgrind, open a terminal to the project directory as root user and run `valgrind --leak-check=full ./ssa_daemon`. The daemon may appear to run slowly as a result of this; this is a feature, not a bug.

## Building the Test Suites

A makefile and shell script are currently in place to make the process of testing as simple as `make all` and `./run_tests.sh`. If compilation fails, try again before digging into what might be the problem; sometimes the problem may be as simple as an open file on your computer that is preventing the compiler from immediately accessing it.

If only one of the test executibles is desired, one may optionally execute `make <test-name>` instead of `make all` to build just that test.

In the future, we will integrate these tests with Jenkins to make the developmental process even more streamlined (it partially because of this that we chose to use GoogleTest, rather a less well-known C testing framework).


## Running the Test Suites

As mentioned in the previous section, a shell script (`.\run_tests.sh`) exists to run all of the test suites found in test_files (barring `top_500`, which would take up an unnecessary amount of time). The flag `-v` may optionally be added if greater detail in error reporting is desired.

If only one test suite needs to be executed, one may simply use the command `./<test-name>` to run a single test. Note that by default this will run the test with verbose errors being output; to silence the extra error logs one can use `./<test-name> 2>/dev/null`.


## Contributing to testing suites

### Adding to an existing test suite file

In each test suite file (such as socket_api_tests.cpp, setsockopt_tests.cpp, etc.) there should first be helper functions and optionally a class that encapsulates the various tests given. After that, there should be a comment labelling the beginning of individual test cases. This is where new test cases can be added. The format for a test case should look like the following:

```c

#include <gtest/gtest.h>
#include "timeouts.h"

TEST_F(TestingSuiteName, YourNewTestCase) {

    TEST_TIMEOUT_BEGIN

    /* code to create socket, perform operations on it here */
    /* ASSERT_EQ(1, my_variable) stops the test on failure */
    /* EXPECT_EQ(2, your_variable) lets the test keeps going, but still fails it in the end */


    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}

```

Note that `TEST_TIMEOUT_BEGIN` and `TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)` are used to set a timeout for how long the code encased between them can run. The code will fail if it reaches the timeout limit before completing. This is particularly useful to us, as we are using system calls that sometimes never return if they fail.

### Creating a new test suite file

TODO: add documentation here