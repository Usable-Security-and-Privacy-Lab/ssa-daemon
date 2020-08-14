/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017-2018, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "log.h"
#include "daemon.h"

#define PORT 8443

int parse_input(int argc, char* argv[], enum log_level *level, char** path);

/* NOTE: This is not the main function that spins up multiple daemons and all
 * the other features that Mark O'Neil implemented. That is found in his repo. 
 * This function is merely to allow easy use of gdb and other
 * debugging tools. */
int main(int argc, char* argv[]) {

    char* config_path = NULL;
    enum log_level level = LOG_WARNING;
    int ret;

    ret = parse_input(argc, argv, &level, &config_path);
    if (ret != 0)
        exit(EXIT_FAILURE);
    

    if (log_init(NULL, level)) {
        fprintf(stderr, "Failed to initialize log\n");
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        log_printf(LOG_ERROR, "Please run as root\n");
        exit(EXIT_FAILURE);
    }

    /* TODO: fork/execve here to make it a true daemon... */
    ret = run_daemon(PORT, config_path);

    log_close();

    /* close stdin, stdout, stderr */
    for (int i = 0; i <= 2; i++)
        close(i);

    return ret;
}

int parse_input(int argc, char* argv[], enum log_level *level, char** path) {

    char* config_path = NULL;
    int log_level_set = 0;

    while (argc > 1) {
        if (argv[1][0] == '-') {
            if (log_level_set) {
                printf("error: only one log level flag allowed (-v or -d)\n");
                return 1;
            }

            if (argv[1][1] == 'v') {
                *level = LOG_INFO;
            
            } else if (argv[1][1] == 'd') {
                *level = LOG_DEBUG;

            } else if (argv[1][1] == 's') {
                *level = LOG_NONE;

            } else {
                printf("unrecognized flag \'%s\'\n", argv[1]);
                return -1;
            }

            if (argv[1][2] != '\0') {
                printf("unrecognized flag \'%s\'\n", argv[1]);
                return -1;
            }
            log_level_set = 1;
        
        } else if (config_path == NULL) {
            config_path = argv[1];
        
        } else {
            printf("unrecognized arg \'%s\'\n", argv[1]);
            return 1;
        }

        argv = &argv[1];
        argc--;
    }

    *path = config_path;
    
    return 0;
}