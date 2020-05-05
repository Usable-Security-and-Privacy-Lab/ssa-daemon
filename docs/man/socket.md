## NAME

socket - create an endpoint for TLS-secured communication

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <in_tls.h>

int socket(int domain, SOCK_STREAM, IPPROTO_TLS);
```

## DESCRIPTION

`socket()` creates a local endpoint for communication, along with an endpoint 
in the SSA Daemon mirroring the attributes of the local endpoint. It returns
a file descriptor that refers to the the local endpoint.

The `domain` argument specifies the protocol family that will be used in 
communication. Formats currently accepted by the SSA are:

  Domain     |    Description
-------------|---------------------------
 AF_INET     |   IPv4 Internet Protocols
 AF_INET6    |   IPv6 Internet Protocols
 AF_HOSTNAME |   Internal Hostname Resolution; Supports IPv4 and IPv6

Note that only TCP-oriented connections are currently supported by the SSA.
The second argument may include the bitwise OR of any of the following values,
to modify the behavior of `socket()`:

Type           | Description
---------------|---------------------------
SOCK_NONBLOCK  | Set the O_NONBLOCK file status flag on the open file description (see open(2)) referred to by the new file descriptor.  Using this flag saves extra calls to fcntl(2) to achieve the same result.
SOCK_CLOEXEC   | Set the close-on-exec (FD_CLOEXEC) flag on the new file descriptor.  See the description of the O_CLOEXEC flag in open(2) for reasons why this may be useful.

## RETURN VALUE

On success, a file descriptor for the new socket is returned.  On error, -1 
is returned, and errno is set appropriately.

## ERRORS

  Errno Code   |   Description
  -------------|---------------
  `ENOMEM`     | Insuffient memory available for alloctions within the SSA daemon.
  `ENOBUFS`    | The SSA daemon's socket hashmap is full.
  
## NOTES

TODO: The errors contained in this man page are incomplete.

TODO: Add information about the AF_HOSTNAME sockaddr struct and whatnot