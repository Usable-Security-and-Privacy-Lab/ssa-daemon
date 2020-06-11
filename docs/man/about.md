# About The Man Pages

These man pages are not meant as a replacement of the POSIX socket man pages.
Rather, they supplement the POSIX socket API with relevant information on
functionality, best practice, and error codes specific to the Secure Socket 
API. All behavior defined in POSIX socket man pages are still relevant to
sockets made using the SSA; however, unspecified behavior or function calls
leading to undefined behavior will be treated in a way that will maintain
the security of all connections held by the SSA Daemon. Such cases will
be outlined in these man pages as well.

The specification of certain behaviors and return codes is as of yet a work in 
progress. For the time being, error codes are subject to change and behavior
additional to the POSIX socket specification is experimental for the time being.