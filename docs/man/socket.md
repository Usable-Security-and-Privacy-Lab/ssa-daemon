## NAME

socket - create an endpoint for TLS-secured communication

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <in_tls.h>

int socket(int domain, int type, int protocol);
```

## DESCRIPTION

`socket()` creates a local endpoint for communication, along with an endpoint 
in the SSA Daemon mirroring the attributes of the local endpoint if `protocol` 
is set as `IPPROTO_TLS`. It returns a file descriptor that refers to the the 
SSA daemon's local endpoint. Encrypted traffic will run through the daemon, 
be encrypted or decrypted passively, and sent via plaintext through this 
channel.

The `domain` argument specifies the protocol family that will be used in 
communication. Formats currently accepted by the SSA are:

  Domain     |    Description
-------------|---------------------------
 AF_INET     |   IPv4 Internet Protocols
 AF_INET6    |   IPv6 Internet Protocols
 AF_HOSTNAME |   Internal Hostname Resolution; Supports IPv4 and IPv6

Only TCP-oriented connections are currently supported by the SSA, so `type` 
must be set to `SOCK_STREAM`. It may optionally also include a bitwise OR of 
any of the following values to modify the behavior of `socket()`:

Type           | Description
---------------|---------------------------
SOCK_NONBLOCK  | Set the O_NONBLOCK file status flag on the open file description (see open(2)) referred to by the new file descriptor.  Using this flag saves extra calls to fcntl(2) to achieve the same result.
SOCK_CLOEXEC   | Set the close-on-exec (FD_CLOEXEC) flag on the new file descriptor.  See the description of the O_CLOEXEC flag in open(2) for reasons why this may be useful.

## RETURN VALUE
On success, a file descriptor for the new socket is returned.  On error, -1 
is returned, and errno is set appropriately.

## ERRORS
The following errors are specific to sockets created using IPPROTO_TLS:

  Errno Code   |   Description
  -------------|---------------
  `ECANCELED`  | The given operation was not able to be completed by the SSA daemon. Look into the logs of the SSA daemon for more information.
  other errors | Consult the POSIX man page for `socket()`. The error returned may apply to either the socket created by the daemon or the socket created within the application--if the error is internal to the daemon's socket then a log message will be reported.

## NOTES
TODO: Add information about the AF_HOSTNAME sockaddr struct and whatnot