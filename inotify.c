/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
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

#include <sys/inotify.h>
#include <unistd.h>

#include "inotify.h"
#include "crl.h"
#include "log.h"


void inotify_cb(struct bufferevent *bev, void *arg) {
	log_printf(LOG_DEBUG, "Read from crl_cache.txt\n");
	//read from "crl_cache.txt", "crl_cache_info.txt"
}

//TODO: what to return??
inotify_ctx* set_inotify(struct event_base* ev_base) {

	int fd; //,wd;
	char buf[BUF_LEN] __attribute__ ((aligned(8)));
	inotify_ctx *inotify = calloc(1, sizeof(inotify_ctx));

	fd = inotify_init();
	inotify->fd = fd;
	/* if (inotify_fd == -1) {
		perror("inotify_init");
		exit(EXIT_FAILURE);
	}*/
	evutil_make_socket_nonblocking(inotify->fd);

	//wd =
	inotify_add_watch(inotify->fd, "crl_cache.txt", IN_CLOSE_WRITE);
	/* if (wd == -1) {
		perror("inotify_add_watch");
		exit(EXIT_FAILURE);
	}*/

	inotify->bev = bufferevent_socket_new(ev_base, inotify->fd, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(inotify->bev, inotify_cb, NULL, NULL, &buf);
	bufferevent_enable(inotify->bev, EV_READ);

	return inotify;
}

void inotify_cleanup(inotify_ctx* inotify) {

    bufferevent_free(inotify->bev);
    close(inotify->fd);
    free(inotify);

}
