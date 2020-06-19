## NAME

getsockopt, setsockopt - get and set TLS-specific options on sockets

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <in_tls.h>

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

```

## DESCRIPTION

`setsockopt()` and `getsockopt()` manipulate options both locally and within the SSA daemon for the socket referred to by the file descriptor `sockfd`. Options at any protocol level will be applied to the daemon's socket as well as the user's socket as long as the socket in question was created using the `IPPROTO_TLS` protocol. 

An additional protocol level (`IPPROTO_TLS`) has been added for sockets 
utilizing the daemon--it exists as a way for a programmer to modify the default 
TLS settings of a socket (such as enabled ciphersuites, message padding 
features, and many other TLS-specific features). This constant can be used in 
`level` alongside one of the defined optnames for the TLS socket options (such 
as `TLS_HOSTNAME` or `TLS_DISABLE_CIPHER`). It should be noted, however, that 
any attempt to programatically make settings weaker than the daemon's 
configuration file (or default settings if no configuration file exists) will 
return an error, so a programmer using these socket options should account for 
the possibility of failure in such calls.

Some of the options given in IPPROTO_TLS only make sense at a certain point in the lifecycle of a connection, such as inserting custom ciphers prior to the TLS handshake of a socket or retrieving a peer's certificate after connecting to them. Any function called


At the `IPPROTO_TLS` level, the options available for `setsockopt()` and 
`getsockopt()` are listed below:

### TLS getsockopt options:

> #### TLS_REMOTE_HOSTNAME
> Sets the hostname to be connected to as a client. 
> The hostname is required in order to verify the validity of a peer's 
> certificate, so any connection made without first setting this option will 
> fail. `optval` should be a NULL-terminated string of the hostname (cannot
> be an IP address).
>
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error
>
> **Errors** 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The hostname was too long and could not be associated with the 
> socket.

> `TLS_DISABLE_CIPHER` - Disables a given cipher from the list of ciphers the
> connection will allow. This function only works for TLS 1.2 ciphers--TLS 1.3
> cipher preferences cannot be changed except in the configuration file. 
> `optval` should be a NULL-terminated string containing the name of exactly 
> one cipher to disable. The cipher's name should be consistend with OpenSSL's 
> naming guidelines (TODO: specify these).
>
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error.
>
> **Errors**
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The specified cipher was not in the cipherlist.

> `TLS_TRUSTED_PEER_CERTIFICATES` - Loads in the list of trusted Certificate 
> Authority (CA) certificates that the socket will verify a peer's certificate
> with. `optval` should be a NULL-terminated string representing the path to
> the given certificate file/directory (TODO: absolute or relative? either?).
> 
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error.
> **Errors**
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The path given in `optval` did not refer to a valid file 
> location.
> - `ECANCELED` - Processing the certificates at the location failed.

> `TLS_CERTIFICATE_CHAIN` - Sets the certificate chain to present to a peer when
> a connection occurs. This option needs to be used before `TLS_PRIVATE_KEY` for
> the certificate/private key combination to be correctly verified. `optval` 
> should be a NULL-terminated string containing the path to the file/directory 
> where the given certificate chain can be found.
>
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error.
>
> **Errors**
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The path given in `optval` was not valid or could not be 
opened.
> - `ECANCELED` - Processing the certificates at the given location failed.


<!-- TODO: add documentation for all setsocket options here -->

### TLS getsockopt options:

<!-- TODO: add documentation for all getsockopt options here -->

## RETURN VALUE

Both functions return 0 on success, or -1 if some error occurred. If -1 is 
returned, `errno` will be set to an error code specifying the reason that
the function failed, and an error string may be set for the TLS socket that 
can be retrieved via the `TLS_ERROR` getsockopt option.
