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


/* NOTE: This is not the main function that spins up multiple daemons and all
 * the other features that Mark O'Neil implemented. That is found in his repo. 
 * This function is merely to allow easy use of gdb and other
 * debugging tools. */
int main(int argc, char* argv[]) {

    char* config_path = NULL;
    int ret = 1;

    log_init();

    if (argc == 2) {
        config_path = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "Too many args passed to ssad on startup\n");
        LOG_E("ssad had too many args passed on startup\n");
        goto out;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Please run ssad as root\n");
        LOG_E("ssad startup attempted without root privilages\n");
        goto out;
    }

    LOG_I("Starting ssad...\n");
    /* TODO: fork/execve here to make it a true daemon... */
    ret = run_daemon(PORT, config_path);

    /* close stdin, stdout, stderr */
    for (int i = 0; i <= 2; i++)
        close(i);

out:
    log_close();

    return ret;
}