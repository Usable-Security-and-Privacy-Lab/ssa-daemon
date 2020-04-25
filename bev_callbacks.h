#ifndef BEV_CALLBACKS_H
#define BEV_CALLBACKS_H

#include <event2/bufferevent.h>



#define MAX_BUFFER	1024*1024*10 /* 10 Megabits */



void common_bev_write_cb(struct bufferevent *bev, void *arg);
void common_bev_read_cb(struct bufferevent *bev, void *arg);

void client_bev_event_cb(struct bufferevent *bev, short events, void *arg);
void server_bev_event_cb(struct bufferevent *bev, short events, void *arg);

#endif