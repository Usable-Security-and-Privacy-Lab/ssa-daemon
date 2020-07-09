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

> #### TLS_DISABLE_CIPHER
> Disables a given cipher from the list of ciphers the
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

> #### TLS_TRUSTED_PEER_CERTIFICATES
> Loads in the list of trusted Certificate 
> Authority (CA) certificates that the socket will verify a peer's certificate
> with. `optval` should be a NULL-terminated string representing the path to
> the given certificate file/directory (TODO: absolute or relative? either?).
> 
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error.
> **Errors**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The path given in `optval` did not refer to a valid file 
> location.
> - `ECANCELED` - Processing the certificates at the location failed.

> #### TLS_CERTIFICATE_CHAIN
> Sets the certificate chain to present to a peer when
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
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - The given socket is already in use.
> - `EINVAL` - The path given in `optval` was not valid or could not be 
> opened.
> - `ECANCELED` - Processing the certificates at the given location failed.


<!-- TODO: add documentation for all setsocket options here -->

### TLS getsockopt options:

> #### TLS_REVOCATION_CHECKS
> Sets the given connection to require a revocation response from some
> authoritative responder. The SSA daemon checks every certificate in a 
> presented certificate chain for revocation status except for the root 
> CA. Checks are done during the `connect()` function--after the TLS 
> handshake but before the connection is fully established. 
> 
> While this option mandates that some form of revocation response is had 
> before a connection is established, it does not set any response methods
> to be used. Thus, it should be used in tandem with one or several of the 
> revocation response methods. The supported response methods are:
> - Certificate Revocation List (CRL) responder, the URLs of which are 
> listed as the AuthorityInformationAccess extension in the peer's certificate.
> See the socket option `TLS_CRL_CHECKS` for more information.
> - Online Certificate Status Protocol (OCSP) responders, the URLs of which 
> are listed as the CRLDistributionPoints extension in the peer's certificate.
> See the socket option `TLS_OCSP_CHECKS` for more information.
> - OCSP Stapled responses, returned as a TLS extension from the server 
> in question. See the socket option `TLS_OCSP_STAPLED_CHECKS` for more 
> information.
> - Cached responses, which require one of the above methods to populate the
> cache and return the same authoritative record for a given host until the
> OCSP response reaches its expiration. See the socket option 
> `TLS_CACHE_REVOCATION` for more information.
>
> These response methods may be used in any combination; however, they are not 
> necessarily all checked every time. As any one response is considered 
> authoritative, the SSA daemon prioritizes faster checks to allow for quicker
> connections. For instance, if all response methods are enabled, the daemon 
> will always check cached responses first, followed by stapled responses (as
> both of the aforementioned options add no latency from establishing a 
> connection with another server). After that, OCSP and CRL responses are 
> queried for simultaneously, with the first authoritative answer being used.
>
> Because the `TLS_REVOCATION_CHECKS` option only enables checks, the values 
> of `optval` and `optlen` are therefore ignored and can be set to any input.
>
> **Restrictions** - The option may not be used if the given socket is already
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. 
>
> A system administrator may configure the SSA daemon to have revocation on
> or off by default, but the `TLS_REVOCATION_CHECKS` socket option may only 
> be used to turn revocation on.
>
> **Error Codes**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - A call to `connect()` or `listen()` has already been done 
> on the socket.

> #### TLS_CRL_CHECKS
> Sets the given connection to query and accept responses from CRL responders
> to determine the revocation status of a peer. Note that 
> `TLS_REVOCATION_CHECKS` determines whether any revocation checks will be 
> performed at all, so setting this option without having it set will still
> result in no revocation checks being performed. CRL responses are not 
> considered authoritative by the SSA daemon unless all CRL distribution points 
> are successfully connected to, queried, and validated.
>
> Because the `TLS_CRL_CHECKS` option only enables checks, the values of 
> `optval` and `optlen` are therefore ignored and can be set to any input.
>
> **Restrictions** - This socket option may not be used if the given socket 
> is already listening, connected or connecting, or if the socket has 
> previously encountered an unrecoverable error. 
>
> A system administrator may configure the SSA daemon to have CRL checks on
> or off by default, but the `TLS_CRL_CHECKS` socket option may only be used 
> to turn revocation on.
>
> **Error Codes**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - A call to `connect()` or `listen()` has already been done 
> on the socket.

> #### TLS_OCSP_CHECKS
> Sets the given connection to query and accept responses from OCSP responders
> to determine the revocation status of a peer. Note that 
> `TLS_REVOCATION_CHECKS` determines whether any revocation checks will be 
> performed at all, so setting this option without having it set will still
> result in no revocation checks being performed. Any one OCSP response that
> has a valid signature and timestamp is considered authoritative by the SSA
> daemon.
>
> Because the `TLS_OCSP_CHECKS` option only enables checks, the values of 
> `optval` and `optlen` are therefore ignored and can be set to any input.
>
> **Restrictions** - This socket option may not be used if the given socket 
> is already listening, connected or connecting, or if the socket has 
> previously encountered an unrecoverable error. 
>
> A system administrator may configure the SSA daemon to have OCSP checks on
> or off by default, but the `TLS_OCSP_CHECKS` socket option may only be used
> to turn revocation on.
>
> **Error Codes**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - A call to `connect()` or `listen()` has already been done 
> on the socket. 

> #### TLS_OCSP_STAPLED_CHECKS
> Sets the given connection to request a stapled OCSP response from the server
> it will connect to. Note that `TLS_REVOCATION_CHECKS` determines whether any 
> revocation checks will be performed at all, so setting this option without 
> having it set will still result in no revocation checks being performed. 
> An OCSP response returned from the server that has a valid signature and 
> timestamp is considered authoritative by the SSA daemon.
>
> Because the `TLS_OCSP_STAPLED_CHECKS` option only enables checks, the values 
> of `optval` and `optlen` are therefore ignored and can be set to any input.
>
> **Restrictions** - This socket option may not be used if the given socket 
> is already listening, connected or connecting, or if the socket has 
> previously encountered an unrecoverable error.
>
> A system administrator may configure the SSA daemon to have stapled OCSP 
> checks on or off by default, but the `TLS_OCSP_STAPLED_CHECKS` socket option 
> may only be used to turn stapled checks on for the given socket.
>
> **Error Codes**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - A call to `connect()` or `listen()` has already been done 
> on the socket.

> #### TLS_CACHE_REVOCATION
> Sets the given connection to accept requests that were previously received
> and cached in the daemon as authoritative responses. OCSP responses are
> supplied with a start and end time within their response, so they can be
> effectively cached and used until their expiration. Responses are usually
> valid for a week, so the SSA daemon caches responses until their expiration
> date or for a week after their issuance date (whichever comes first). Note 
> that `TLS_REVOCATION_CHECKS` determines whether any revocation checks will be 
> performed at all, so setting this option without having it set will still 
> result in no revocation checks being performed. An OCSP response returned from 
> the server that has a valid signature and timestamp is considered 
> authoritative by the SSA daemon.
>
> Because the `TLS_CACHE_REVOCATION` option only enables caching, the values 
> of `optval` and `optlen` are therefore ignored and can be set to anything.
>
> **Restrictions** - This socket option may not be used if the given socket 
> is already listening, connected or connecting, or if the socket has 
> previously encountered an unrecoverable error. 
>
> A system administrator may configure the SSA daemon to have revocation caching 
> on or off by default, but the `TLS_CACHE_REVOCATION` socket option may only be 
> used to turn revocation caching on.
>
> **Error Codes**
> - `EBADFD` - The given socket has previously encountered an unrecoverable 
> error.
> - `EOPNOTSUPP` - A call to `connect()` or `listen()` has already been done 
> on the socket.


## RETURN VALUE

Both functions return 0 on success, or -1 if some error occurred. If -1 is 
returned, `errno` will be set to an error code specifying the reason that
the function failed, and an error string may be set for the TLS socket that 
can be retrieved via the `TLS_ERROR` getsockopt option. See the `errno` error 
codes listed for each individual option above.
