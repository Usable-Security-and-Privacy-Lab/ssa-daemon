% ACCEPT(2) Version 0.67 | Secure Socket API Documentation

NAME
====

accept - accept an incoming encrypted connection on a socket

SYNOPSIS
========

**#include <sys/types.h>**  
**#include <sys/socket.h>**  

**int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);**  

DESCRIPTION
===========

**accept()** extracts the first connection request on the queue of pending 
connections for the listening socket _sockfd_, creates a new connected socket, 
and returns a new file descriptor referring to that socket. The queue of 
pending connections comes from the SSA daemon, and have already been 
validated/encrypted. Note that any connections that fail to validate over the TLS 
handshake will be dropped, so calls to **accept()** will not always accurately represent 
the actual number of incoming TCP connections.

RETURN VALUE
============

On success, zero is returned. On error, -1 is returned, and _errno_ is set 
appropriately.

ERRORS
======

|  Errno Code  |   Description                                                 |
|:-------------|:--------------------------------------------------------------|
|`ECONNABORTED`| A connection was accepted, but encountered an error before finishing setup within the daemon. |
| other errors | Consult the POSIX socket man pages. |

NOTES
=====

While instances are rare, a listening socket may fail at some point during use. 
If this is the case, the next call to `accept()` will return an appropriate 
error.

AUTHORS
=======

Nathaniel Bennett <me@nathanielbennett.com>

SEE ALSO
========

**accept**(2), **listen-tls**(2), **tls**(7)