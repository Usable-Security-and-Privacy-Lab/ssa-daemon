
CXXFLAGS=-Wall -Wno-deprecated-declarations
GTESTFLAGS=-lgtest_main -lgtest -pthread
SSLFLAGS=-lssl -lcrypto

all: badssl top500

badssl: badssl.cpp helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o badssl badssl.cpp helper_functions.h helper_functions.o \
			$(GTESTFLAGS)

top500: top_500.cpp helper_functions.h helper_functions.o
	g++ $(CXXFLAGS) -o top500 top_500.cpp helper_functions.h \
		helper_functions.o $(GTESTFLAGS)


helper_functions.o: helper_functions.c helper_functions.h
	gcc -c $(CXXFLAGS) helper_functions.c

clean:
	rm -f helper_functions.o
	rm -f badssl
	rm -f top500
