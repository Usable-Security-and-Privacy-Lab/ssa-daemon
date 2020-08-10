#ifndef SSA_DAEMON_INOTIFY_H
#define SSA_DAEMON_INOTIFY_H

#include <event2/bufferevent.h>
#include <event2/event.h>

struct inotify_ctx_st;

typedef struct inotify_ctx_st inotify_ctx;

struct inotify_ctx_st {

    struct bufferevent *bev;
    int fd;

};




inotify_ctx* set_inotify(struct event_base* ev_base);

void inotify_cleanup(inotify_ctx* inotify);


#endif
