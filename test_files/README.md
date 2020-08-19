# Testing Documentation

## Purpose
The purpose of this documentation is to outline how to build, run, and add to 
the testing suites developed for the SSA daemon. Testing is an important part 
of any project, and even more so for projects that are meant to run for an 
arbitrary amount of time in the background (such as daemons) or projects that 
implement essential security/crypto measures (such as TLS). As such, 
comprehensive tests should be written after each addition to the SSA Daemon 
to ensure that no regressions make their way into the system. This guide will 
walk through the testing framework that is in place for the project and give 
instruction on adding tests to it.

The testing library currently in use for the Daemon is GoogleTest. While basic information is given on the GoogleTest library here, readers should refer to [the GoogleTest documentation](https://github.com/google/googletest/blob/master/googletest/docs/primer.md) for a more complete guide.


## Prerequisites
- Make sure that gcc is installed. To check this, run `which gcc` in the 
terminal; the path to the gcc executible should be printed out (usually 
/usr/bin/gcc). If gcc is not installed then run `sudo apt-get install gcc` 
if running Ubuntu and `sudo dnf install gcc` if runing a Debian variant. 
- Make sure that g++ is installed. Do the above steps, but with `g++` 
in place of `gcc`.
- Do the same for `make` and `cmake` as well.
- Download and install the googletest library using the following steps:
  1. Install libgtest-dev (`sudo apt-get install libgtest-dev`). 
  2. Go to the googletest source that has now been installed 
  (`cd /usr/src/gtest`). 
  3. Make the source files into a library using cmake 
  (`sudo cmake CMakeLists.txt` followed by `sudo make`).
  4. Go to the 'lib' directory (`cd lib`)
  5. Copy the library files to the appropriate library folder 
  (`sudo cp *.a /usr/lib`). 
- Download the SSA kernel module from 
[here](https://github.com/Usable-Security-and-Privacy-Lab/ssa), build 
the module as root user, and load the module in to the kernel. 
To do this, follow these commands: 
  1. `git clone https://github.com/Usable-Security-and-Privacy-Lab/ssa` 
  2. `cd ssa`
  3. `sudo su` (and type in your password)
  4. `make`
  5. `insmod ssa.ko`
- Download the SSA daemon from 
[here](https://github.com/Usable-Security-and-Privacy-Lab/ssa) and build 
the daemon. To do this, follow these commands: 
  1. `git clone https://github.com/Usable-Security-and-Privacy-Lab/ssa-daemon` 
  2. `cd ssa-daemon`
  3. `make`

Once these dependencies are properly installed, the test suites can be built.

## Building and Running the Test Suites

The Makefile used for building the SSA daemon has been configured so that it 
will automatically build test cases. It does this by:
  1. Building the servers found in test_cases/servers/ into executibles
  2. Building the files found in test_cases/testutil/ into object files.
  3. Building every .cpp file found in test_cases/ into an individual test 
  case with testutil/*.o objects compiled in.
  4. Building one comprehensive executible containing all of the aforementioned 
  test suites.

Simply running `make test` will build all of the test cases and servers, and 
then execute the comprehensive test case executible. Individual tests may be 
run simply by building all of the tests, then executing the desired test 
(such as `./test_files/speed_test`).

## Contributing to Testing Suites

The current testing framework is built in such a way that additional test 
suites can be easily added. Adding a test suite is as simple as creating a new 
.cpp file within test_files/; all the building and linking steps are performed 
automatically from there.

Current test suites are built in such a way that clients and servers can both 
be tested for correct usage conditions while operating via the SSA daemon. 
On start up, a given test suite will `fork()` a child process that will then 
run an instance of the SSA daemon with superuser privelages (the test suite 
itself does not need to be executed with superuser privileges; it will prompt 
for a password once the tests have started). After the daemon has ran its 
setup, it will send a signal back to the test cases. In the meantime, the 
test suite blocks until the signal arrives, then `fork()` another child process 
to start an instance of a server that utilizes the SSA daemon. Once again, the 
test suite parent blocks until the server has completed setup and sent back a 
signal. After all this, the test suite begins its individual tests. This allows 
the test suite to perform the client side of connections aimed towards the 
server if such testing functionality is desired. If at any time the daemon or 
the server crashes, the test suite will fail and clean up any resources. 
Once the test suite has completed its tests, it will kill the server and the 
daemon.

All of this functionality has been abstracted out to a single macro:
```c
#define INIT_TESTS(suite_name, daemon_config, server_path)
```

In this macro, `suite_name` refers to the name of the test suite in use; 
`daemon_config` should be the path to a .yml configuration file that the daemon 
will use; and `server_path` should point to an executible server found in 
test_files/servers/. If `server_path` is NULL, a server will not be started. 
This macro should be before any of the test cases listed in the test suite 
file. The googletest test cases that come after it should be of the form 
`TEST_F(suite_name, test_name)` (where `suite_name` is the same as the 
`suite_name` in INIT_TESTS and `test_name` is a unique name to identify 
the test with). This is the only macro needed for the daemon and the server 
to be fully run as part of the test suites.

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