
CXXFLAGS=-Wall -Wno-deprecated-declarations
GTESTFLAGS=-lgtest_main -lgtest -pthread
SSLFLAGS=-lssl -lcrypto

all: helpers badssl

helpers:
	gcc -c $(CXXFLAGS) helper_functions.c

badssl:
	g++ $(CXXFLAGS) -o badssl badssl.cpp helper_functions.h helper_functions.o \
			$(GTESTFLAGS)



clean:
	rm -f helper_functions.o
	rm -f badssl
