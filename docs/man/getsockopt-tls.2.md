% GETSOCKOPT(2) Version 0.67 | Secure Socket API Documentation

NAME
====

getsockopt, setsockopt - get and set TLS-specific options on sockets

SYNOPSIS
========

**#include <sys/types.h>**  
**#include <sys/socket.h>**  
**#include <in_tls.h>**  
  
| __int getsockopt(int__ *sockfd***, int** *level***, int** *optname***,**  
|                __void \*__*optval***, socklen_t \****optlen***);** 

DESCRIPTION
===========

**getsockopt**() retrieves information both locally and within the SSA daemon for 
the socket referred to by the file descriptor _sockfd_.

An additional protocol level (**IPPROTO_TLS**) has been added for sockets 
utilizing the daemon--it exists as a way for a programmer to retrieve the TLS 
settings of a socket (such as enabled ciphersuites, message padding features, 
and many other TLS-specific features). This constant can be used in _level_ 
along with one of the defined optnames for the TLS socket options (such as 
**TLS_HOSTNAME** or **TLS_DISABLE_CIPHER**). 

Some of the options given in IPPROTO_TLS only make sense at a certain point in 
the lifecycle of a connection, such as retrieving a peer's certificate after 
connecting to an end host. Any getsockopt**() function used at the wrong phase 
in a socket's life cycle will return the error code **EOPNOTSUPP**.

At the **IPPROTO_TLS** level, the options available for **getsockopt**() are listed 
below:

### TLS getsockopt options:


> #### TLS_CONTEXT
> Retrieves an identifier that allows a user to replicate the given socket's 
> settings and session cache in another TLS socket.
> 
> A TLS Context is an ID that references the internal settings and session 
> cache of another socket. It can be used to easily copy over applied settings 
> from one socket to many others, and it allows for session reuse when multiple 
> client sockets reuse the same TLS context. It is best used by creating a 
> socket that will remain unused for the duration of the program, apply all 
> desired settings to that socket, and then get the TLS context of the socket 
> and apply it to each connection afterwards. 
> 
> `optval` should point to an unsigned long that will be populated with the TLS 
> context ID of the socket being operated on, and `optlen` should be equal to 
> `sizeof(unsigned long)`.
> 
> **RESTRICTIONS**
> 
> IMPORTANT: In cases where TLS contexts are used, NO settings (other than 
> TLS_HOSTNAME) should be modified for any sockets using the TLS context once 
> it has been shared with other sockets, as undefined behavior will occur.
> 
> The option may not be used if the given socket is already listening, 
> connected or connecting, or if the socket has previously 
> encountered an unrecoverable error.
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` isn't a valid TLS context ID, the socket 
> associated with the context ID `optval` has been closed, or `optlen` is not 
> equal to `sizeof(unsigned long)`). 

#

> #### TLS_SESSION_REUSE
> Determines whether the given socket has session caching and reuse enabled. 
>
> TLS Sessions store and save the private keys associated with a connection 
> so that a client may reconnect to a server at a future time without 
> performing a full handshake or re-validating the server's certificate. 
> This allows for much faster handshake speeds.
>
> `optval` should point to an integer value that will be populated with 
> either `0` or `1`, and `optlen` should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> This option may be used on any valid TLS file descriptor. 
>
> **ERRORS**
> 
> - `EINVAL` - Bad input (`optval` was null, or `optlen` not the right size/ 
> null). 

#





## RETURN VALUE

`getsockopt()` return 0 on success, or -1 if some error occurred. If -1 is 
returned, `errno` will be set to an error code specifying the reason that
the function failed, and an error string may be set for the TLS socket that 
can be retrieved via the `TLS_ERROR` getsockopt option. For a list of 
possible errno codes that may be returned, see the **ERRORS** section in each 
option above.

