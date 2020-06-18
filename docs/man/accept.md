## NAME

accept - accept an encrypted connection on a socket

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

## DESCRIPTION

`accept()` extracts the first connection request on the queue of pending 
connections for the listening socket, `sockfd`, creates a new connected socket, 
and returns a new file descriptor referring to that socket. The queue of 
pending connections comes from the SSA daemon, and have already been 
validated/encrypted. Note that any connections that fail to validate over the TLS 
handshake will be dropped, so calls to `accept()` will not always accurately represent 
the actual number of TCP connections accepted.

## RETURN VALUE

On success, zero is returned. On error, -1 is returned, and `errno` is set 
appropriately.

## ERRORS

  Errno Code     |   Description
  ---------------|---------------
  `ECONNABORTED` | A connection was accepted, but encountered an error before finishing setup within the daemon.
  other errors   | Consult the POSIX socket man pages.

## NOTES

A listening socket may fail at some point during use. If this is the case, the next call to `accept()` will return an appropriate error.