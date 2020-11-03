## NAME

setsockopt - set TLS-specific options on sockets

## SYNOPSIS

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <in_tls.h>

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

```

## DESCRIPTION

`setsockopt()` applies options both locally and within the SSA daemon for the 
socket referred to by the file descriptor `sockfd`. Options at any protocol 
level will be applied to the daemon's socket as well as the user's socket as 
long as the socket in question was created using the `IPPROTO_TLS` protocol. 

An additional protocol level (`IPPROTO_TLS`) has been added for sockets 
utilizing the daemon--it exists as a way for a programmer to modify the default 
TLS settings of a socket (such as enabled ciphersuites, message padding 
features, and many other TLS-specific features). This constant can be used in 
`level` alongside one of the defined optnames for the TLS socket options (such 
as `TLS_HOSTNAME` or `TLS_DISABLE_CIPHER`). It should be noted, however, that 
any attempt to programatically make settings weaker than the daemon's 
configured defaults (as specified in the daemon's configuration file ) will 
return the error `EPROTO`, so a programmer using these socket options should 
account for the possibility of failure in such calls. 

Some of the options given in IPPROTO_TLS only make sense at a certain point in 
the life cycle of a connection, such as inserting custom ciphers prior to a 
TLS handshake or retrieving a peer's certificate after connecting. Any 
`setsockopt()` function used at the wrong phase in a socket's life cycle will 
return the error code `EOPNOTSUPP`.

In some cases, a socket may fail an operation in an unrecoverable way while 
a `setsockopt()`, `connect()` or other system call is being performed on it. 
In such cases, the socket will be put in an error state, and any system calls 
performed on it will return `EBADFD`.


At the `IPPROTO_TLS` level, the options available for `setsockopt()` are 
listed below:

### TLS Setsockopt Options:



> #### TLS_REMOTE_HOSTNAME
> Sets the hostname that will be connected to for a client connection. 
> The hostname is required in order to verify the validity of a peer's 
> certificate, so any connection made without first setting this option will 
> fail. `optval` should be a NULL-terminated string of the hostname (cannot 
> be an IP address), and `optlen` should be the entire length of the string 
> (including the null-terminating byte).
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. 
>
> **ERRORS** 
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use (see **Restrictions**). 
> - `EINVAL` - The hostname was too long and could not be associated with the 
> socket.

#

> #### TLS_DISABLE_CIPHER
> Disables a given cipher from the list of ciphers that will be selected from 
> when performing a TLS handshake. This function only works for TLS 1.2 
> ciphers; TLS 1.3
> cipher preferences cannot be changed except in the configuration file. 
> `optval` should be a NULL-terminated string containing the name of exactly 
> one cipher to disable. The cipher's name should be consistend with OpenSSL's 
> naming guidelines (TODO: specify these). `optlen` should be the entire length 
> of the string (including the null-terminating byte). 
>
> **RESTRICTIONS** 
>
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. 
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **Restrictions**). 
> - `EINVAL` - The specified cipher was not in the cipherlist. 

#

> #### TLS_TRUSTED_PEER_CERTIFICATES
> Loads in the list of trusted Certificate Authority (CA) certificates that 
> will be used to verify a peer's certificate with. `optval` should be a 
> null-terminated string representing the path to the given certificate 
> file/directory (TODO: absolute or relative? either?). 
> 
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. 
> 
> **ERRORS**
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - The path given in `optval` did not refer to a valid file/folder 
> location. 
> - `ECANCELED` - Processing the certificates at the location failed. 

#

> #### TLS_CERTIFICATE_CHAIN
> Sets the certificate chain to be used for a TLS handshake. This option must 
> be used before `TLS_PRIVATE_KEY` or else the certificate/private key 
> combination will not be correctly verified. `optval` should be a 
> null-terminated string containing the path to the file/directory where the 
> given certificate chain can be found. 
> 
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. 
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - The path given in `optval` was not valid or could not be 
> opened. 
> - `ECANCELED` - Processing the certificates within the SSA daemon failed. 

#

> #### TLS_MIN_VERSION
> Sets the minimum TLS version that the socket will accept during the TLS 
> handshake. Defined versions are `TLS_1_0`, `TLS_1_1`, `TLS_1_2`, and 
> `TLS_1_3`. `optval` should be a short assigned to one of the four 
> versions, which are defined as macros in `<in_tls.h>`. `optlen` should 
> be equal to `sizeof(short)`. 
>
> **RESTRICTIONS**
>
> The option may not be used if the given socket is already listening, 
> connecting or connected, or if the socket has previously encountered an 
> unrecoverable error. The minimum TLS version should not be set greater than 
> the currently-set maximum TLS version for a given socket; attempts to do 
> so will result in failure with the `EINVAL` errno code set.
> 
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**).
> - `EINVAL` - The value passed in `optval` was not valid (either too big or 
> too small).

#

> #### TLS_MAX_VERSION
> Sets the maximum TLS version that the socket will accept during the TLS 
> handshake. Defined versions are `TLS_1_0`, `TLS_1_1`, `TLS_1_2`, and 
> `TLS_1_3`. `optval` should be a short assigned to one of the four 
> versions, which are defined as macros in `<in_tls.h>`. `optlen` should 
> be equal to `sizeof(short)`. 
>
> **RESTRICTIONS**
>
> The option may not be used if the given socket is already listening, 
> connecting or connected, or if the socket has previously encountered an 
> unrecoverable error. The maximum TLS version should not be set less than 
> the currently-set minimum TLS version for a given socket; attempts to do 
> so will result in failure with the `EINVAL` errno code set.
> 
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**).
> - `EINVAL` - The value passed in `optval` was not valid (either too big or 
> too small).

#

> #### TLS_PRIVATE_KEY
> Sets the private key to be used in association with the loaded certificate 
> chain. This option must be used after `TLS_CERTIFICATE_CHAIN` or else the 
> certificate/private key combination will not be correctly verified. `optval` 
> should be a null-terminated string containing the path to the 
> file/directory where the given certificate chain can be found.
> 
> **RESTRICTIONS**
>
> The option may not be used if the given socket is already listening, 
> connecting or connected, or if the socket has previously encountered an 
> unrecoverable error.
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket.
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**).
> - `EINVAL` - The path given in `optval` was not valid or could not be opened. 
> - `ECANCELED` - Processing the private key within the SSA daemon failed.

#

> #### TLS_REVOCATION_CHECKS
> Sets the given connection to require a revocation response from some 
> authoritative responder. The SSA daemon requires every certificate in a 
> presented certificate chain to have a valid revocation status (except for the 
> root CA, which is impossible to check). Checks are done during the 
> `connect()` function, after the TLS handshake but before the system call 
> returns.
> 
> While this option mandates that some form of revocation response is had 
> before a connection is established, it does not set any response methods 
> to be used. Thus, it needs to be used in tandem with one or several of the 
> available revocation response methods. The supported response methods are: 
> - Certificate Revocation List (CRL) responders (see `TLS_CRL_CHECKS`). 
> - Online Certificate Status Protocol (OCSP) responders (see 
> `TLS_OCSP_CHECKS`). 
> - OCSP Stapled responses, a TLS extension that is sometimes supported 
> by servers (see `TLS_OCSP_STAPLED_CHECKS`). 
> - Cached responses, which are previous checks that are saved in the SSA 
> daemon until they expire (see `TLS_CACHE_REVOCATION`). 
> 
> These response methods may be used in any combination; however, they are not 
> necessarily all checked every time. As any one response is considered 
> authoritative, the SSA daemon prioritizes faster checks to allow for quicker 
> connections. For instance, if all response methods are enabled, the daemon 
> will always check cached responses first, followed by stapled responses (as 
> both of the aforementioned options add almost no latency). After that, OCSP 
> and CRL responses are  queried for simultaneously, with the first 
> authoritative answer being used.
> 
> If no definitive response is received from the enabled methods, the SSA 
> daemon will reject the connection and return an error string explaining that 
> the certificate's revocation status could not be determined. 
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. In addition, this option may not be used 
> to disable revocation checks if the SSA daemon's configuration has them 
> enabled. 
>
> **ERRORS**
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to disable revocation checks when the 
> SSA daemon configuration had it enabled. 

#

> #### TLS_CRL_CHECKS
> Sets the given socket to query and accept responses from CRL responders 
> to determine the revocation status of a peer. Note that 
> `TLS_REVOCATION_CHECKS` determines whether any revocation checks will be 
> performed at all, so setting this option without having it set will still 
> result in no revocation checks being performed. CRL responses are not 
> considered authoritative by the SSA daemon unless all CRL distribution points 
> for a certificate are successfully connected to, queried, and verified. 
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
> encountered an unrecoverable error. In addition, this option may not be used 
> to enable CRL-based revocation checks if the SSA daemon configuration had 
> it disabled. 
>
> **ERRORS** 
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to enable CRL-based revocation checks 
> when the SSA daemon configuration had it disabled. 

#

> #### TLS_OCSP_CHECKS
> Sets the given socket to query and accept responses from OCSP responders 
> to determine the revocation status of a peer. Note that 
> `TLS_REVOCATION_CHECKS` determines whether any revocation checks will be 
> performed at all, so setting this option without having it set will still 
> result in no revocation checks being performed. Any one OCSP response that 
> has a valid signature and timestamp is considered authoritative by the SSA 
> daemon. 
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already listening, 
> connected or connecting, or if the socket has previously encountered an 
> unrecoverable error. In addition, this option may not be used to enable OCSP 
> revocation checks if the SSA daemon configuration has it disabled. 
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to enable CRL-based revocation checks 
> when the SSA daemon configuration had it disabled. 

#

> #### TLS_OCSP_STAPLED_CHECKS
> Sets the given socket to request a stapled OCSP response from the server 
> it will connect to. Note that `TLS_REVOCATION_CHECKS` determines whether any 
> revocation checks will be performed at all, so setting this option without 
> having it set will still result in no revocation checks being performed. 
> An OCSP response returned from the server that has a valid signature and 
> timestamp is considered authoritative by the SSA daemon. 
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already listening, 
> connected or connecting, or if the socket has previously encountered an 
> unrecoverable error. In addition, this option may not be used to enable OCSP 
> stapling if the SSA daemon configuration has it disabled. 
>
> **ERRORS**
>
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to enable stapled OCSP revocation 
> checks when the SSA daemon configuration had it disabled. 

#

> #### TLS_CACHED_REV_CHECKS
> Sets the given socket to accept requests that were previously received 
> and cached in the daemon as authoritative responses. OCSP responses are 
> supplied with a start and end time within their response, so they can be 
> effectively cached and used until their expiration (which is capped at seven 
> days after issuance). Note that `TLS_REVOCATION_CHECKS` determines whether 
> any revocation checks will be performed at all, so setting this option 
> without having it set will still result in no revocation checks being 
> performed. An OCSP response returned from the server that has a valid 
> signature and timestamp is considered authoritative by the SSA daemon. 
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already listening, 
> connected or connecting, or if the socket has previously encountered an 
> unrecoverable error. In addition, this option may not be used to enable 
> cached revocation checks if the SSA daemon configuration has it disabled. 
>
> **ERRORS**
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to enable revocation cache checks 
> when the SSA daemon configuration had it disabled. 

#

> #### TLS_CONTEXT
> Sets the given socket's settings and session caches to mirror those of 
> another socket.
> 
> A TLS Context is an ID that references the internal settings and session 
> cache of another socket. It can be used to easily copy over applied settings 
> from one socket to many others, and it allows for session reuse when multiple 
> client sockets reuse the same TLS context. It is best used by creating a 
> socket that will remain unused for the duration of the program, apply all 
> desired settings to that socket, and then get the TLS context of the socket 
> and apply it to each connection afterwards. 
> 
> `optval` should point to an unsigned long representing the TLS context ID 
> of some other socket, and `optlen` should be equal to 
> `sizeof(unsigned long)`.
> 
> **RESTRICTIONS**
> 
> IMPORTANT: In cases where TLS contexts are used, NO settings (other than 
> TLS_HOSTNAME) should be modified for any sockets using the TLS context once 
> it has been shared with other sockets, as undefined behavior will occur.
> 
> The option may not be used if the given socket is already 
> listening, connected or connecting, or if the socket has previously 
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
> Sets the given socket to cache and reuse sessions (whether as client or 
> server).
>
> TLS Sessions store and save the private keys associated with a connection 
> so that a client may reconnect to a server at a future time without 
> performing a full handshake or re-validating the server's certificate. 
> This allows for much faster handshake speeds.
>
> `optval` should point to an integer value of either `1` or `0`, and `optlen` 
> should be equal to `sizeof(int)`. 
>
> **RESTRICTIONS** 
> 
> The option may not be used if the given socket is already listening, 
> connected or connecting, or if the socket has previously encountered an 
> unrecoverable error. In addition, this option may not be used to enable 
> cached revocation checks if the SSA daemon configuration has it disabled. 
>
> **ERRORS**
> 
> - `EBADFD` - An unrecoverable error has previously occurred on the socket. 
> - `EOPNOTSUPP` - The given socket is already in use (see **RESTRICTIONS**). 
> - `EINVAL` - Bad input (`optval` not 1 or 0, or `optlen` not the right size). 
> - `EPROTO` - The system call attempted to enable revocation cache checks 
> when the SSA daemon configuration had it disabled. 

#

## RETURN VALUE

`setsockopt()` return 0 on success, or -1 if some error occurred. If -1 is 
returned, `errno` will be set to an error code specifying the reason that
the function failed, and an error string may be set for the TLS socket that 
can be retrieved via the `TLS_ERROR` getsockopt option. For a list of 
possible errno codes that may be returned, see the **ERRORS** section in each 
option above.
