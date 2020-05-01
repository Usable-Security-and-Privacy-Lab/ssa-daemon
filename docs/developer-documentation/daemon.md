# Daemon Documentation

## Purpose 
The developer documentation is for developers who want to contribute to the SSA (if you are a developer hoping to utilize the SSA in your application, see docs/user-documentation.md). It is intended to help developers understand the SSA codebase and to explain how to make changes to the SSA and where those changes should happen. 

It may be helpful for developers to familiarize themselves with the documentation found in `install-documentaion.md`, `user-documentation.md` and `admin-documentation.md` (all found in the `docs` directory).

This document contains information specific to the ssa-daemon. For information specific to the kernel module, see `module.md`. For information about the ssa in general, see `general.md`.

## Descriptions of files in the ssa-daemon repository
**docs** - folder containing documentation for users, admins, developers and testing

**examples** -  folder containing simple example client and server that use SSA

**extras** -  folder containing files for add-on features, most notably addons.c which adds support for the address family AF_HOSTNAME (ADD CROSS REFERENCE)

**test_files** - folder containing various files for testing. The .gitignore file ignores all files in this folder 

**config.c/h** - source files for parsing the config files ssa.cfg and ssa.conf

**daemon.c/h** - source files defining the event loop and associated callback functions

**hashmap.c/h** - implementation of a hashmap that maps unsigned longs to void pointers. Used by the daemon to keep track of the sockets it is managing

**hashmap_str.c/h** - implementation of a hashmap that maps strings to void pointers. Used by config.c

**in_tls.h** - file defining constants and structs that should be available to an application using SSA. This is the SSA equivalent of "in.h"

**install_packages.sh** - script for installing dependencies required by the SSA-Daemon

**issue_cert.c/h** - 

**log.c/h** - source files defining SSA-Daemon's logging functionality

**main.c** - source file defining start-up for the SSA-Daemon

**netlink.c/h** - source files defining SSA-Daemon's communication with the SSA kernel module using Netlink

**openssl_compat.c/h** - 

**queue.c/h** - source files defining a queue that does not appear to actually be used by any other files

**self_sign.c/h** - 

**ssa.cfg** - configuration file used by a system administrator to specify standards and settings for TLS connections made by the SSA 

**ssa.conf** - configuration file used by a system administrator to specify standards and settings for TLS connections made by the SSA 

**tb_communications.h** - this file and the tb_connector files (below) provide support for the SSA-Daemon to communicate with the Trustbase application to perform certificate validation (see the trustbase_verify function in tls_wrapper.c).c  Currently, this functionality is not enabled.

**tb_connector.c/h** - see "tb_communications.h"

**tls_wrapper.c/h** - source files defining functions used to manage the TLS connection

## Adding to the SSA Admin Configuration File

To add different options to the administrator configuration file (ssa.cfg or ssa.conf) the following steps need to be followed. 

1. Add the appropiate flag to the ssa_config_t struct found in config.h.
2. Add a case in config.c in the function config.c that captures what the setting name is.
3. Set the appropiate flag based on the parsing in config.c

For example, if I wanted to add a value called foo to the configuration file, and have its value be set to bar, I would have to add the following.
1. In config.c add a ```char* foo ```to the ssa_config_t struct
2. Go to add_setting function in config.c and add an else if (STR_MATCH(name, "foo"))...
3. Set the config->foo value to be whatever value was found (in this case bar)

## Understanding OpenSSL
The ssa-daemon uses the OpenSSL library to implement TLS connections. For help understanding OpenSSL, please consult `openssl.md`, found in this directory.