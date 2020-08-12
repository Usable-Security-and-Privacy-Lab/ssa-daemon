CC = gcc
CPP = g++
FLAGS = -Wall
DEBUG_FLAGS = -ggdb3
RELEASE_FLAGS = -Ofast

EXEC = ssa_daemon
TEST_EXEC = all_tests

SOURCES = $(wildcard *.c)
HEADERS = $(wildcard *.h)
OBJECTS = $(SOURCES:.c=.o)

TEST_C_UTIL := $(wildcard test_files/testutil/*.c)
TEST_CXX_UTIL := $(wildcard test_files/testutil/*.cpp)
TEST_OBJECTS := $(TEST_C_UTIL:.c=.o) $(TEST_CXX_UTIL:.cpp=.o)

SERVER_FILES := $(wildcard test_files/servers/*.c)
TEST_FILES = $(wildcard test_files/*.cpp)

TEST_SERVERS := $(patsubst %.c,%,$(SERVER_FILES))
TESTS := $(patsubst %.cpp,%,$(TEST_FILES))

INCLUDES = `pkg-config --cflags libnl-3.0`
TEST_LIBS=-lgtest_main -lgtest -pthread
LIBS = -lpthread -lyaml  \
	`pkg-config --libs   \
		libevent_openssl \
		libnl-genl-3.0   \
	    openssl          \
	`
all: debug

debug: FLAGS += $(DEBUG_FLAGS)
debug: $(EXEC)

release: FLAGS += $(RELEASE_FLAGS)
release: $(EXEC)

test: debug $(TEST_SERVERS) test_files/$(TEST_EXEC) $(TESTS) 
	cd test_files && ./$(TEST_EXEC)

# To remove generated files
clean:
	rm -f $(EXEC)
	rm -f *.o
	rm -f test_files/$(TEST_EXEC)
	rm -f $(TESTS)
	rm -f $(TEST_SERVERS)
	rm -f test_files/testutil/*.o tests/testutil/*.h.gch


# Main target
$(EXEC): $(OBJECTS) $(HEADERS)
	$(CC) $(OBJECTS) $(LIBS) -o $(EXEC)

# To obtain object files
%.o:: %.c
	$(CC) -c $(FLAGS) $< $(INCLUDES)



test_files/$(TEST_EXEC): $(TEST_OBJECTS) $(TEST_FILES)
	$(CPP) $(FLAGS) $^ $(TEST_LIBS) -o $@

# To obtain executibles, object files for tests
test_files/%:: test_files/%.c 
	$(CC) $(FLAGS) $< -o $@

test_files/%:: test_files/%.cpp $(TEST_OBJECTS)
	$(CPP) $(FLAGS) $^ $(TEST_LIBS) -o $@

test_files/testutil/%.o:: test_files/testutil/%.c
	$(CC) -c $(FLAGS) $< -o $@

test_files/testutil/%.o:: test_files/testutil/%.cpp
	$(CPP) -c $(FLAGS) $< $(TEST_LIBS) -o $@








