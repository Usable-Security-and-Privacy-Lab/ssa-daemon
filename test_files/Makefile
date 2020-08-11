CC = gcc
CPP = g++
FLAGS=-Wall 
CXX_LIBS=-lgtest_main -lgtest -pthread

ALL_TESTS=all_tests

C_SOURCES := $(wildcard testutil/*.c)
CXX_SOURCES := $(wildcard testutil/*.cpp)
OBJECTS = $(C_SOURCES:.c=.o) $(CXX_SOURCES:.cpp=.o)

SERVER_FILES := $(wildcard servers/*.c)
TEST_FILES = $(wildcard *.cpp)

SERVERS := $(patsubst %.c,%,$(SERVER_FILES))
TESTS := $(patsubst %.cpp,%,$(TEST_FILES))


all: $(OBJECTS) $(SERVERS) $(TESTS) $(ALL_TESTS)

test: $(ALL_TESTS)
	./$(ALL_TESTS)

$(ALL_TESTS): $(OBJECTS) $(TEST_FILES)
	$(CPP) $(FLAGS) $^ $(CXX_LIBS) -o $@

%:: %.c 
	$(CC) $(FLAGS) $< -o $@

%:: %.cpp $(OBJECTS)
	$(CPP) $(FLAGS) $^ $(CXX_LIBS) -o $@

testutil/%.o:: testutil/%.c
	$(CC) -c $(FLAGS) $< -o $@

testutil/%.o:: testutil/%.cpp
	$(CPP) -c $(FLAGS) $< $(CXX_LIBS) -o $@



clean:
	rm -f $(TESTS)
	rm -f $(SERVERS)
	rm -f testutil/*.o testutil/*.h.gch
