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
	log_printf(LOG_ERROR, "set_inotify\n");
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

    log_printf(LOG_ERROR, "inotify_cleanup\n");
    bufferevent_free(inotify->bev);
    close(inotify->fd);
    free(inotify);

}
