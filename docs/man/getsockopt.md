## NAME

getsockopt, setsockopt - get and set TLS-specific options on sockets

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <in_tls.h>

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

```

## DESCRIPTION

`getsockopt()` retrieves information both locally and within the SSA daemon for 
the socket referred to by the file descriptor `sockfd`.

An additional protocol level (`IPPROTO_TLS`) has been added for sockets 
utilizing the daemon--it exists as a way for a programmer to retrieve the TLS 
settings of a socket (such as enabled ciphersuites, message padding features, 
and many other TLS-specific features). This constant can be used in `level` 
along with one of the defined optnames for the TLS socket options (such as 
`TLS_HOSTNAME` or `TLS_DISABLE_CIPHER`). 

Some of the options given in IPPROTO_TLS only make sense at a certain point in 
the lifecycle of a connection, such as retrieving a peer's certificate after 
connecting to an end host. Any `getsockopt()` function used at the wrong phase 
in a socket's life cycle will return the error code `EOPNOTSUPP`.

At the `IPPROTO_TLS` level, the options available for `getsockopt()` are listed 
below:

### TLS getsockopt options:

> #### TLS_COMPRESSION
> Determines whether TLS compression is enabled for the given socket. If the 
> socket is connected to a peer at the time this function is called, it will 
> report whether the connection is actively using compression. 
>
> `optval` should point to an integer, and `optlen` should be equal to 
> `sizeof(int)`. `optval` will return `1` if compression is on, and `0` if off. 
>
> **ERRORS**
> - `EINVAL` - Bad input (`optlen` not the right size). 






## RETURN VALUE

`getsockopt()` return 0 on success, or -1 if some error occurred. If -1 is 
returned, `errno` will be set to an error code specifying the reason that
the function failed, and an error string may be set for the TLS socket that 
can be retrieved via the `TLS_ERROR` getsockopt option. For a list of 
possible errno codes that may be returned, see the **ERRORS** section in each 
option above.

