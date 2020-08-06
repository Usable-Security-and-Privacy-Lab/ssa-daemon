CC = gcc
CPP = g++
FLAGS=-Wall 
CXX_LIBS=-lgtest_main -lgtest -pthread


C_SOURCES := $(wildcard testutil/*.c)
CXX_SOURCES := $(wildcard testutil/*.cpp)

OBJECTS = $(C_SOURCES:.c=.o) $(CXX_SOURCES:.cpp=.o)
TESTS := $(patsubst %.cpp,%,$(wildcard *.cpp))


all: test

test: $(OBJECTS) $(TESTS) 



%:: %.cpp
	$(CPP) $(FLAGS) $(OBJECTS) $^ $(CXX_LIBS) -o $@

testutil/%.o:: testutil/%.c
	$(CC) -c $(FLAGS) $< -o $@

testutil/%.o:: testutil/%.cpp
	$(CPP) -c $(FLAGS) $< $(CXX_LIBS) -o $@



clean:
	rm -f $(TESTS)
	rm -f testutil/*.o testutil/*.h.gch