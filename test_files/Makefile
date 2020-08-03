
CXXFLAGS=-Wall -Wno-deprecated-declarations
GTESTFLAGS=-lgtest_main -lgtest -pthread
SSLFLAGS=-lssl -lcrypto

all: helper_functions.o badssl top_500 socket_api_tests client_sessions

badssl: badssl.cpp timeouts.h helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o badssl badssl.cpp timeouts.h helper_functions.h helper_functions.o $(GTESTFLAGS)

top_500: top_500.cpp timeouts.h helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o top_500 top_500.cpp timeouts.h helper_functions.h helper_functions.o $(GTESTFLAGS)

socket_api_tests: socket_api_tests.cpp timeouts.h helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o socket_api_tests socket_api_tests.cpp timeouts.h helper_functions.h helper_functions.o $(GTESTFLAGS)

client_sessions: client_sessions.cpp timeouts.h helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o client_sessions client_sessions.cpp timeouts.h helper_functions.h helper_functions.o $(GTESTFLAGS)

helper_functions.o: helper_functions.cpp helper_functions.h
	g++ -c $(CXXFLAGS) helper_functions.cpp helper_functions.h $(GTESTFLAGS)

clean:
	rm -f helper_functions.o
	rm -f badssl
	rm -f top_500
	rm -f setsockopt_tests
	rm -f sessions_client