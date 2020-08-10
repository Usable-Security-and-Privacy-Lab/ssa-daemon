#ifndef SSA_CONNECTION_CALLBACKS_H
#define SSA_CONNECTION_CALLBACKS_H

#include <event2/bufferevent.h>

#define MAX_BUFFER    1024*1024*10 /* 10 Megabits */


/**
 * Bufferevents automatically read data in from their fd to their read buffer,
 * as well as reading data out from their write buffer to their fd. All that
 * these callbacks to is notify you when these read/write operations have been
 * triggered. Since we don't modify the watermarks of the read_cb, it is 
 * triggered every time new information is read in from a file descriptor, and
 * never stops reading. 
 * This write_cb has functionality that works in tandem with the read callback;
 * when too much data has been put into the write buffer (out_buf >= MAX_BUFFER)
 * the read_cb temporarily disables itself from reading in new data and sets
 * the other bufferevent's writing watermarks so that it will not trigger
 * a write callback until half of that data has been written out. Once that
 * happens, the write_cb re-enables the other bufferevent's reading capabilities
 * and resets its own writing watermarks to 0, so that its write_cb will not be
 * triggered until no data is left to be written.
 * Note that this function is not called every time a write operation occurs, 
 * and it certainly does not cause data to be written from the write buffer to
 * the fd. It merely reports once all data to be written from a buffer has been
 * written.
 * @param bev The bufferevent that the write callback has been triggered for.
 * @param arg the context of the socket using the given bufferevent.
 */
void common_bev_write_cb(struct bufferevent *bev, void *arg);


/**
 * Every time data is read into a bufferevent from its associated fd, this
 * function will be called. It takes that data and writes it to the write buffer
 * of the other bufferevent. If too much data is being fed through, the read 
 * operation of this bufferevent will be turned off until the other buffer has
 * written enough data out.
 * @param bev The bufferevent that the write callback has been triggered for.
 * @param arg the context of the socket using the given bufferevent.
 */
void common_bev_read_cb(struct bufferevent *bev, void *arg);


/**
 * A callback triggered whenever the given bufferevent has any new events happen
 * to it. The event may be a connection completion, an error, an end-of-file, or
 * a timeout (see Libevent documentation for any other possible events).
 * Multiple events may be present when a callback is triggered--they are 
 * combined together as flags. The functionality associated with each individual
 * event can be found in the event handler functions below.
 * @param bev The bufferevent that the write callback has been triggered for.
 * @param events The event flags that resulted in this callback being evoked.
 * @param arg the context of the socket using the given bufferevent.
 */
void client_bev_event_cb(struct bufferevent *bev, short events, void *arg);


/**
 * A callback triggered whenever the given bufferevent has any new events happen
 * to it. The event may be a connection completion, an error, an end-of-file, or
 * a timeout (see Libevent documentation for any other possible events).
 * Multiple events may be present when a callback is triggered--they are 
 * combined together as flags. The functionality associated with each individual
 * event can be found in the event handler functions below.
 * @param bev The bufferevent that the write callback has been triggered for.
 * @param events The event flags that resulted in this callback being evoked.
 * @param arg the context of the socket using the given bufferevent.
 */
void server_bev_event_cb(struct bufferevent *bev, short events, void *arg);

#endif