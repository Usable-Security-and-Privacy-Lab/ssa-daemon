# Admin Documentation

## Purpose
The purpose of this README is to explain to administrators how to use the SSA. 
It includes the different settings administrators can use, what they do, and 
how to create an admin config file.

This README is a WIP and can be changed as needed.

## Setting the Administrator File
The SSA reads a configuration file to set the administrator security settings. 
By defaults it reads "config.yml" as the configuration file.

If you wish to change the default, simply pass in a command-line argument when 
starting up the SSA daemon indicating the path to the configuration file.

## Creating a Config File
The config file must be made in the .yml format. Details of the format can be 
found [here](https://learnxinyminutes.com/docs/yaml).

## Administator Settings 
(taken from config_options.c in the SSA daemon source code):

Settings may be listed in any order, but may only be listed once in a 
configuration file. The following settings are available for configuration: 

|      Configuration Label     |                   Description                 |
| :--------------------------: | :-------------------------------------------- |
| **cert-transparency-checks** | indicates whether Certificate Transparency restrictions will be enforced on certificates being authenticated by the SSA. The value for this field should either be `enabled` or `disabled`. |
| **cert-verification-depth**  | designates the maximum length that a certificate chain may be for the SSA daemon to accept the certificate. The value for this field should be a positive integer value. |
| **tlsv1.2-ciphers**          | the order of preferred ciphers to use for connections using TLSv1.2 and earlier. The value for this field should be a bulleted list of individual cipher names. For a list of accepted cipher names, see [here](https://www.openssl.org/docs/man1.0.2/man1/ciphers.html). Note that some of these ciphers may be weak or may disable encryption (such as the NULL ciphers); these should not be used and will be expressely blocked by the SSA daemon in a future release. |
| **tlsv1.3-ciphers**          | the order of preferred ciphers to use for connections using TLSv1.3. The value for this field should be a bulleted list of individual cipher names. The following ciphers are accepted: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, and `TLS_AES_128_CCM_8_SHA256`. Note the CCM ciphers were included in the TLSv1.3 standard to accommadate embedded devices; as such, they are generally less secure than the AES or CHACHA20 ciphers. |
| **min-tls-version**          | the minimum permissible TLS version that will be used to negotiate TLS handshakes. The value for this field is an integer corresponding to the desired TLS version--`0` for TLSv1.0, `1` for TLSv1.1, etc. SSLv2.0 and SSLv3.0 cannot be enabled due to inherent vulnerabilities within them. |
| **max-tls-version**          | the maximum permissible TLS version that will be used to negotiate TLS handshakes. The value for this field is an integer corresponding to the desired TLS version--`0` for TLSv1.0, `1` for TLSv1.1, etc. SSLv2.0 and SSLv3.0 cannot be enabled due to inherent vulnerabilities within them. |
| **revocation-checks**        | indicates whether revocation should be mandated on TLS connections as a whole. If this field is enabled, any connection that fails to retrieve an OCSP or CRL response will not allow for a connection to be completed. The value for this field should either be `enabled` or `disabled`. |
| **revocation-cached**        | indicates whether revocation responses will be cached and reused by the daemon or not. Revocation responses have a set validity period, which is stored and checked by the daemon. That validity period is ensured to be no more than 1 week by the daemon. The value for this field should either be `enabled` or `disabled`. |
| **revocation-crl**           | indicates whether CRL distribution points will be queried to determine revocation status when such distribution points are present within a certificate. The value for this field should either be `enabled` or `disabled`. Note that not all Certificate Authorities use CRLs as a revocation--CAs such as LetsEncrypt only include OCSP responders within signed certificates. |
| **revocation-ocsp**          | indicates whether OCSP responders will be queried to determine revocation status when such responder URLs are present within a certificate. The value for this field should either be `enabled` or `disabled`. |
| **revocation-stapled**       | indicates whether OCSP responses stapled on server certificates will be considered during the revocation checking process. Stapled OCSP responses are by far the fastest of any of the three methods to retrieve revocation responses, and they are as secure as any other way of retrieving OCSP responses. The value for this field should either be `enabled` or `disabled`. |
| **session-resumption**       | indicates whether TLS sessions will be resumed when such sessions are shared from connection to connection. Session resumption can dramatically reduce TLS connection startup times as it effectively reuses symmetric keys already negotiated in a previous connection with a server. Methods of session resumption include session keys and session tickets. The value for this field should either be `enabled` or `disabled`. |
| **session-timeout**          | indicates how long a TLS session will be considered valid and reusable by the daemon. The value for this field should be a positive integer value representing the time for which a TLS session is valid, measured in seconds. |
| **trust-store-location**     | indicates where the SSA Daemon should pull its store of trusted Certificate Authority certificates from. By default, the daemon will use the operating system's set of trusted CAs. If a custom set of CAs is desired, this field should be set to the file or folder path containing PEM-encoded root certificates. |

## Notes
Configuration is currently in the process of being better-integrated into the userspace daemon.
When we finalize the configuration API, it will be specified here and on [owntrust.org](https://owntrust.org).
See [our paper](https://www.usenix.org/conference/usenixsecurity18/presentation/oneill) for a preview of the types of configuration options administrastors will have.