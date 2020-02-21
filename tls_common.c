#include "tls_common.h"
#include "log.h"

void associate_fd(connection* conn, evutil_socket_t ifd) {
	bufferevent_setfd(conn->plain.bev, ifd);
	bufferevent_enable(conn->plain.bev, EV_READ | EV_WRITE);

	log_printf(LOG_INFO, "plain bev enabled\n");
	return;
}

