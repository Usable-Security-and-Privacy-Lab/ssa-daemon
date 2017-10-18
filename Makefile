CC = gcc
CC_FLAGS = -w -g -Wall
 
EXEC = tls_wrapper
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = -I/usr/include/libnl3
LIBS = -lnl-3 -lnl-genl-3 -levent_openssl -levent -lcrypto -lssl
 
# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CC_FLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
