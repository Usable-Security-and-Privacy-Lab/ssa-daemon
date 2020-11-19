% TLS(7) Version 0.67 | Secure Socket API Documentation

NAME
====

tls - TLS protocol

SYNOPSIS
========

**#include <sys/socket.h>**  
**#include <sys/types.h>**  
**#include <in_tls.h>**  
  
**tls_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);**  

DESCRIPTION
===========

**Talk about TLS protocol, SSA daemon and OpenSSL here**

**Talk about Address formats**

**Talk about SysAdmin configuration file and its options**

**Socket Options section (header just in bold)**

**Sockets API section**

**Error handling**

FILES
=====

**Talk about config file and its options**

ERRORS
======

**List errnos here**

VERSIONS
========

AUTHORS
=======

Nathaniel Bennett <me@nathanielbennett.com>

SEE ALSO
========

**accept-tls(2)**, **bind-tls(2)**, **connect-tls(2)**, **getsockopt-tls(2)**, **listen-tls(2)**, **socket-tls(2)**, **tcp(7)**, **socket(7)**

(Note that the manpages for socket function behavior specific to the SSA daemon can be found by appending '-tls' to the function title)

owntrust.org for additional up-to-date online documentation.

RFC 2246 for the TLS 1.0 specification.
RFC 5246 for the TLS 1.2 specification.
RFC 7301 for the TLS Application-Layer Protocol Network (ALPN) specification.
RFC 8446 for the TLS 1.3 specification.
