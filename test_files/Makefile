CC = gcc
CPP = g++
FLAGS=-Wall -Wno-deprecated-declarations
CXX_LIBS=-lgtest_main -lgtest -pthread


C_SOURCES := $(wildcard testutil/*.c) #TODO: will testutil/ work?
CXX_SOURCES := $(wildcard testutil/*.cpp)
HEADERS := $(wildcard testutil/*.h)
OBJECTS = $(C_SOURCES:.c=.o) $(CXX_SOURCES:.cpp=.o) #TODO: will concatenating multiple work?

TEST_SOURCES := $(wildcard *.cpp)
TESTS: $(TEST_SOURCES:.cpp=)

test: $(TESTS)

$(TEST_SOURCES): $(OBJECTS)
	$(CPP) $(FLAGS) $(HEADERS) $(OBJECTS) $(CXX_LIBS) -o $@

testutil/%.o: testutil/%.c
	$(CC) -c $(FLAGS) $< -o $@

testutil/%.o: testutil/%.cpp
	$(CPP) -c $(FLAGS) $< $(CXX_LIBS) -o $@


clean: clean-objects
	rm -f badssl
	rm -f top_500
	rm -f setsockopt_tests
	rm -f sessions_client

clean-objects:
	rm -f testutil/*.o
