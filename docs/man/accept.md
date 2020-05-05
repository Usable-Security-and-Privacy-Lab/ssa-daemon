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
validated/encrypted.

## RETURN VALUE

On success, zero is returned. On error, -1 is returned, and `errno` is set 
appropriately. 

## ERRORS

  Errno Code     |   Description
  ---------------|---------------
  `EBADFD`       | The socket that `sockfd` refers to is in a bad state (for instance, it already failed a previous call to `listen`).
  `EINVAL`       | The socket that `sockfd` refers to is not a listening socket.
  `EBADF`        | The daemon could not find the socket associated with `sockfd`.

## NOTES

`EOPNOTSUPP` is not listed in the errors, as the standard man pages state that 
`EINVAL` should be returned if the socket is not listening for connections. So, 
in this special case, the function will return `EINVAL` instead of `EOPNOTSUPP` 
if the socket is not in the right state.

A listening socket may fail at some point during use. If this is the case, the next call to `accept()` will return an appropriate error.