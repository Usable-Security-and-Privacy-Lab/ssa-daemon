% CONNECT(2) Version 0.67 | Secure Socket API Documentation

NAME
====

connect - initiate a TLS connection

SYNOPSIS
========

**#include <sys/types.h>**  
**#include <sys/socket.h>**  

**int connect(int** _sockfd_**, const struct sockaddr \***_addr_**, socklen_t** _addrlen_**);**  

DESCRIPTION
===========

The **connect**() system call connects the daemon's socket associated with 
_sockfd_ to the address specified by _addr_. When that connection has been 
established and the TLS handshake is complete, the kernel then connects the
local socket to the daemon and begins to transfer information between the 
secure external connection and the plaintext local connection.

The socket may only **connect**() once--whether the connection attempt 
succeeds or fails, any subsequent calls to **connect**() (or **listen**()) on
the socket will fail with errno code **EOPNOTSUPP** (unless the connection 
is nonblocking and is in the process of connecting).

TODO: Figure out how this works with AF_UNSPEC

RETURN VALUE
============

If the connection is established between the daemon and the address, the TLS 
handshake succeeds, and the internal connection to the daemon is established, 
then 0 will be returned. If an error occured during connection or validation, 
-1 is returned, and _errno_ is set appropriately.

ERRORS
======

|                |                                                             |
|----------------|-------------------------------------------------------------|
|  Errno Code    |   Description                                               |
|**EBADF**       | No socket exists in the daemon that is associated with _sockfd_. |
|**EBADFD**      | The socket that _sockfd_ refers to is in a bad state (such as if it already failed a previous call to **connect**()). |
|**ECONNABORTED**| The user-to-daemon or daemon-to-address connection process failed. |
|**EPROTO**      | The TLS handshake failed--usually because the server didn't validate or support strong enough encryption standards. |
|**EOPNOTSUPP**  | The socket was not in the right state to connect (such as if **listen**() had already been called on _sockfd_) |
|**ECANCELED**   | The SSA daemon encountered an internal failure while connecting. Consult the logs for more information. |

AUTHORS
=======

Nathaniel Bennett <me@nathanielbennett.com>
