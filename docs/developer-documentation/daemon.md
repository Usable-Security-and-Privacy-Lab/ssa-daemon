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

**config.c/h** - source files for parsing the config file specified on the daemon's startup (default: test_files/config.yml)

**connection_callbacks.c/h** - source files that define/operate on bufferevent callbacks for various connections (secure-facing, plain-facing and revocation connection callbacks are all defined and implemented in these files)

**daemon.c/h** - source files defining the event loop and callback functions directly associated with the POSIX socket system calls

**hashmap.c/h** - implementation of a hashmap that maps unsigned longs or strings to void pointers. Used by the daemon to keep track of the sockets it is managing, and to cache OCSP responses for future use.

**in_tls.h** - file defining constants and structs that should be available to an application using SSA. This is the SSA equivalent of "in.h"

**install_packages.sh** - script for installing dependencies required by the SSA-Daemon

**log.c/h** - source files defining SSA-Daemon's logging functionality

**main.c** - source file defining start-up for the SSA-Daemon

**netlink.c/h** - source files defining SSA-Daemon's communication with the SSA kernel module using Netlink

**error.c/h** - source files defining functions related to converting OpenSSL errors to errno equivalents, and assigning error strings to particular sockets.

**daemon_structs.c/h** - source files defining structures used commonly in the daemon, as well as functions that create/destroy/operate on said structures.

**revocation.c/h** - source files for operating on revocation structures and determining revocation status. Note: functions that establish or deal with HTTP connections for the sake of revocation are found in connection_callbacks.c/h.

**socket_setup.c/h** - source files containing functions that assist in creating/beginning connections made by the daemon.

**sockopt_functions.c/h** -source files containing functions to deal with

## Adding to the SSA Admin Configuration File

To add different options to the administrator configuration file (config.yml) the following steps need to be followed:

1. Add the appropriate data type to the global_config struct found in daemon_structs.h
2. Add a `#define` with the name of your setting (as a string) near the top of config.c. This will be the key the config parser searches for within the file
3. Within the function `parse_next_setting()` (found in config.c), add an `else if`to the long if statement chain. In this if statement you add, you should compare the parsed setting to see if it matches the string you defined at the top of the file. Use `strcmp()` for this.
4. Use one of the predefined functions to parse the value of the setting (such as a boolean, a string, an integer) and put it into the data type you added to the global_config struct. If no predefined function fits your use case, feel free to make a new one, following the general approach of the other functions.
5. Now your setting will be loaded into that struct on start up. If no setting is specified, your setting will default to 0 or its equivalent (such as NULL for a string).

If no configuration file can be found, a struct will be made using the default configurations found (see function `default_settings_new()`). Make sure you set this to load in the securest default.


## Understanding OpenSSL
The ssa-daemon uses the OpenSSL library to implement TLS connections. For help understanding OpenSSL, please consult `openssl.md`, found in this directory.