## NAME

listen - listen for TLS connections on a socket

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>

int listen(int sockfd, int backlog);
```

## DESCRIPTION

`listen()` sets the socket referred to by `sockfd` to passively accept 
incoming connection requests using `accept()`. It also sets the SSA daemon's 
socket to do the same. As incoming connections are received by the daemon, it 
performs TLS handshakes and establishes an encrypted connection. Following 
this, it will launch a connection attempt on the socket referred to by 
`sockfd`. This connection will be handled once the user calls `accept()`.

## RETURN VALUE

On success, zero is returned. On error, -1 is returned, and `errno` is set 
appropriately. 

## ERRORS

  Errno Code     |   Description
  ---------------|---------------
  `EBADF`        | No socket exists in the daemon that is associated with `sockfd`.
  `EBADFD`       | The socket that `sockfd` refers to is in a bad state (for instance, it already failed a previous call to `listen`).
  `EOPNOTSUPP`   | The socket that `sockfd` refers to is already being used or has been used (for instance, `connect()` or `listen()` have already been called on it).
   other errors  | Consult the POSIX man pages for `listen()`

  
## NOTES

A listening socket may fail at some point during use. If this is the case, the next call to `accept()` will return an appropriate error.