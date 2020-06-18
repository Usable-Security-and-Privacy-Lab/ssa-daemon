
CXXFLAGS=-Wall -Wno-deprecated-declarations
GTESTFLAGS=-lgtest_main -lgtest -pthread
SSLFLAGS=-lssl -lcrypto

all: badssl top_500 setsockopt_tests socket_api_tests

badssl: badssl.cpp helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o badssl badssl.cpp helper_functions.h helper_functions.o \
			$(GTESTFLAGS)

top_500: top_500.cpp helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o top_500 top_500.cpp helper_functions.h \
		helper_functions.o $(GTESTFLAGS)

setsockopt_tests: setsockopt_tests.cpp timeouts.h 
	g++ $(CXXFLAGS) -o setsockopt_tests setsockopt_tests.cpp \
		helper_functions.h $(GTESTFLAGS)

socket_api_tests: socket_api_tests.cpp timeouts.h 
	g++ $(CXXFLAGS) -o socket_api_tests socket_api_tests.cpp \
		helper_functions.h $(GTESTFLAGS)

helper_functions.o: helper_functions.c helper_functions.h
	gcc -c $(CXXFLAGS) helper_functions.c

clean:
	rm -f helper_functions.o
	rm -f badssl
	rm -f top_500
	rm -f setsockopt_tests