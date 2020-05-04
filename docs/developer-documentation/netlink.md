# Understanding Netlink and Generic-Netlink
*Written by Nathaniel Bennett*

*In Progress: this documentation is not finished.*

### Introduction

Netlink is a standard means of inter-process and kernel communication for regular programs, created by the developers of the Linux kernel. It utilizes the same BSD Sockets interface that most network connections do, and its libraries are generally included by default in the kernel. 

As our use of netlink involves programming both in user space and in the linux kernel, this guide will be broken up into two sections. 
We will first discuss the process of establishing a netlink connection and of communication from a program to the kernel. We will then discuss the creation of a generic netlink program from the kernel side, along with any aspects of connection or communication unique to the kernel.

### Generally Helpful Pointers
* This guide will not cover everything you'll need to know about netlink; however, the actual source code of netlink does, hard as it may be to traverse :). 
The information that makes up this guide was mostly derived from the [downloadable source code](https://github.com/thom311/libnl), as well as from some helpful (if not potentially outdated) [libnl API documentation](https://www.infradead.org/~tgr/libnl/doc/api/index.html). 
These are where you will be able to find any additional help.
* `libnl` refers to the library that contains netlink and generic-netlink. `genl` or `genetlink` simply refers to generic netlink.

## Using Netlink in User Space

### Step 1: Setting Up and Connecting a Netlink Socket
* As was mentioned before, Netlink operates using the standard BSD Sockets interface:
    ```C
    int socket(int domain, int type, int protocol)
    ```

    To create a new netlink socket, one should use the `AF_NETLINK` domain, and have `SOCK_RAW` as the connection type.
    Some commonly used protocols include `NETLINK_ROUTE` and `NETLINK_FIREWALL`, but for generic-netlink this parameter is set to `NETLINK_GENERIC`.

    This interface could technically be used alone, but it would require us to ensure that correct information be stored in headers, byte paddings be set the right way, and so forth.

* The `libnl` package gives an additional wrapping around this interface in order to ensure the robustness and security of information sent and received.

#### Allocating a New Socket

* To allocate a netlink socket, one can call `nl_socket_alloc()`. This function returns a reference to a `nl_sock` struct.
* Memory Cleanup: Use `nl_socket_free(struct nl_sock *sock)` to free the socket after use.

#### Setting a Socket's Local/Remote Port

* To set the local port that the netlink socket should communicate using, call `nl_socket_set_local_port(struct nl_sock *sk, int port)`.
    If `port` is set to 0 then a unique port will randomly assigned.
* To set the remote port that the netlink socket should exclusively communicate with (somewhat akin to `bind`), use `nl_socket_set_peer_port(struct nl_sock *sk, int port)`.

#### Connecting
* To connect to the generic netlink protocol, simply call `genl_connect(struct nl_sock *sk)`.
* Memory Cleanup: Call `nl_close(struct nl_sock *sk)` when done with the connection.
* Error checking: `genl_connect` returns 0 on success, negative error code on failure. `nl_close` does not return diagnostic information.