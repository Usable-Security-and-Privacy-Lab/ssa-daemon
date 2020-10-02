#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>

#include <openssl/err.h>
#include <openssl/ocsp.h>

#include "connection_callbacks.h"
#include "daemon_structs.h"
#include "error.h"
#include "log.h"
#include "netlink.h"
#include "revocation.h"


void handle_client_connected(socket_ctx* sock_ctx, channel* startpoint);
void handle_client_error(socket_ctx* sock_ctx, channel* startpoint);
void handle_client_eof(socket_ctx* sock_ctx, channel* startpoint);

void handle_server_connected(socket_ctx* sock_ctx, channel* startpoint);
void handle_server_error(socket_ctx* sock_ctx, channel* startpoint);
void handle_server_eof(socket_ctx* sock_ctx, channel* startpoint);


/*
 *******************************************************************************
 *                  CONNECTION BUFFEREVENT CALLBACK FUNCTIONS
 *******************************************************************************
 */

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
void common_bev_write_cb(struct bufferevent *bev, void *arg) {

    socket_ctx* sock_ctx = (socket_ctx*) arg;
    channel* endpoint = (bev == sock_ctx->secure.bev) ? &sock_ctx->plain : &sock_ctx->secure;
    
    /*
    log_printf(LOG_DEBUG, "write event on bev %p (%s)\n", bev, 
            (bev == sock_ctx->secure.bev) ? "secure" : "plain");
     */

    if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
        bufferevent_enable(endpoint->bev, EV_READ);
    }
    return;
}

/**
 * Every time data is read into a bufferevent from its associated fd, this
 * function will be called. It takes that data and writes it to the write buffer
 * of the other bufferevent. If too much data is being fed through, the read 
 * operation of this bufferevent will be turned off until the other buffer has
 * written enough data out.
 * @param bev The bufferevent that the write callback has been triggered for.
 * @param arg the context of the socket using the given bufferevent.
 */
void common_bev_read_cb(struct bufferevent* bev, void* arg) {
    /* TODO: set read high-water mark?? */
    
    socket_ctx* sock_ctx = (socket_ctx*) arg;
    channel* endpoint = (bev == sock_ctx->secure.bev) 
            ? &sock_ctx->plain : &sock_ctx->secure;
    struct evbuffer* in_buf;
    struct evbuffer* out_buf;
    size_t in_len;

    /*
    log_printf(LOG_DEBUG, "read event on bev %p (%s)\n", bev, 
            (bev == sock_ctx->secure.bev) ? "secure" : "plain");
    */

    in_buf = bufferevent_get_input(bev);
    in_len = evbuffer_get_length(in_buf);
    if (in_len == 0)
        return;

    /* clear read buffer if already closed */
    if (endpoint->closed == 1) {
        LOG_D("drained buffer.\n");
        evbuffer_drain(in_buf, in_len);
        return;
    }

    /* copy content to the output buffer of the other bufferevent */
    out_buf = bufferevent_get_output(endpoint->bev);
    evbuffer_add_buffer(out_buf, in_buf);

    if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
        LOG_D("Overflowing buffer, slowing down\n");

        bufferevent_setwatermark(endpoint->bev, 
                EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
        bufferevent_disable(bev, EV_READ);
    }
    return;
}


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
void client_bev_event_cb(struct bufferevent *bev, short events, void *arg) {

    socket_ctx* sock_ctx = (socket_ctx*) arg;
    channel* startpoint = (bev == sock_ctx->secure.bev)
            ? &sock_ctx->secure : &sock_ctx->plain;

    if (events & BEV_EVENT_ERROR)
        handle_client_error(sock_ctx, startpoint);
    else if (events & BEV_EVENT_EOF)
        handle_client_eof(sock_ctx, startpoint);
    else if (events & BEV_EVENT_CONNECTED)
        handle_client_connected(sock_ctx, startpoint);
}


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
void server_bev_event_cb(struct bufferevent *bev, short events, void *arg) {

    socket_ctx* sock_ctx = (socket_ctx*) arg;
    int is_secure_channel = (bev == sock_ctx->secure.bev) ? 1 : 0;
    
    channel* startpoint = (is_secure_channel) ? &sock_ctx->secure : &sock_ctx->plain;

    if (events & BEV_EVENT_ERROR)
        handle_server_error(sock_ctx, startpoint);
    else if (events & BEV_EVENT_EOF)
        handle_server_eof(sock_ctx, startpoint);
    else if (events & BEV_EVENT_CONNECTED)
        handle_server_connected(sock_ctx, startpoint);
}

/*******************************************************************************
 *                CLIENT BUFFEREVENT CALLBACK HELPER FUNCTIONS
 ******************************************************************************/


/**
 * Handles an error event for a client bufferevent and determines whether the 
 * daemon should keep the connection alive or close it (designated by 
 * startpoint->closed and endpoint->closed). 
 * @param sock_ctx The context of the socket that received the error.
 * @param error The OpenSSL error that the particular bufferevent encountered.
 * Note that this could be '0', designating no error--either `errno` errors
 * or OpenSSL errors may be present when an error event is received.
 * @param startpoint The channel of the socket that received the error event.
 * @param endpoint The other channel of the socket.
 */
void handle_client_error(socket_ctx* sock_ctx, channel* startpoint) {

    unsigned long error = bufferevent_get_openssl_error(startpoint->bev);
    channel* endpoint = (startpoint == &sock_ctx->secure)
                ? &sock_ctx->plain : &sock_ctx->secure;
    daemon_ctx* daemon = sock_ctx->daemon;
    unsigned long id = sock_ctx->id;

    LOG_I("Client %s endpoint encountered error\n",
        (startpoint->bev == sock_ctx->secure.bev) 
                ? "encrypted" : "plaintext");

    /* TODO: errno is unreliable. getsockopt(SO_ERROR) might be better */
    if (errno == ECONNRESET || errno == EPIPE)
        LOG_I("Connection closed by local user\n");
    else if (errno != 0)
        LOG_W("Unhandled error %i has occurred: %s\n", errno, strerror(errno));
    else
        LOG_E("SSL error occurred on endpoint: %s\n", 
                    ERR_reason_error_string(error));


    startpoint->closed = 1;

    if ((evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0)
                && endpoint->closed == 0)
        endpoint->closed = 1;


    if (endpoint->closed == 1) {
        if (sock_ctx->state == SOCKET_CONNECTING)
            netlink_handshake_notify_kernel(daemon, id, -EPROTO);

        if ((sock_ctx->state == SOCKET_FINISHING_CONN)
                    && (sock_ctx->rev_ctx != NULL))
            netlink_handshake_notify_kernel(daemon, id, ECONNRESET);           

        socket_shutdown(sock_ctx);
        sock_ctx->state = SOCKET_ERROR;
    }
}


/**
 * Handles an EOF event by closing both channels in a socket context.
 * @param sock_ctx The context of the socket that received an EOF on
 * one of its bufferevents.
 * @param startpoint The channel of the socket that received the EOF.
 * @param endpoint The other channel of the socket. 
 */
void handle_client_eof(socket_ctx* sock_ctx, channel* startpoint) {

    channel* endpoint = (startpoint == &sock_ctx->secure)
                ? &sock_ctx->plain : &sock_ctx->secure;
    daemon_ctx* daemon = sock_ctx->daemon;
    unsigned long id = sock_ctx->id;
    int is_unclean_shutdown = 0;

    LOG_D("client %s channel got EOF\n", 
                (startpoint->bev == sock_ctx->secure.bev) 
                ? "encrypted" : "plaintext");


    if (startpoint == &sock_ctx->secure)
        startpoint->closed = 1;

    /* shutdown is unclean if (encrypted) peer closed w/out sending SSL shutdown */
    if (sock_ctx->secure.closed && !sock_ctx->plain.closed
                && !(SSL_get_shutdown(sock_ctx->ssl) & SSL_RECEIVED_SHUTDOWN)) {
        
        LOG_W("TLS shutdown wasn't clean\n");
        is_unclean_shutdown = 1;
    }

    if (startpoint == &sock_ctx->plain)
        startpoint->closed = 1;



    if (bufferevent_getfd(endpoint->bev) == -1)
        endpoint->closed = 1;

    if (endpoint->closed == 0) {
        if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
            LOG_D("Channel still had data to be read from it--flushing...\n");
            common_bev_read_cb(endpoint->bev, sock_ctx);
        }

        if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0)
            endpoint->closed = 1;
    }


    if (endpoint->closed == 1) {
        if (sock_ctx->state == SOCKET_CONNECTING)
            netlink_handshake_notify_kernel(daemon, id, -ECONNREFUSED);
        
        if ((sock_ctx->state == SOCKET_FINISHING_CONN)
                    && (sock_ctx->rev_ctx != NULL))
            netlink_handshake_notify_kernel(daemon, id, -ECONNRESET);

        /* only clean shutdowns should get SSL_shutdown() */
        if (is_unclean_shutdown)
            sock_ctx->state = SOCKET_DISCONNECTED; 

        socket_shutdown(sock_ctx);
        sock_ctx->state = SOCKET_DISCONNECTED;
    }
}


/**
 * Handles the case where the client channel's secure bufferevent connected 
 * successfully; this is not called when the plain channel is connected. 
 * When accept_cb is called, the socket passed in is already connected,
 * so when it is associated with the plain channel bufferevent 
 * (in associate_fd()) it will not trigger the connected event.
 * @param conn The connection context associated with the triggered bufferevent.
 * @param daemon The daemon's context.
 * @param id The id of the socket context associated with this bufferevent.
 * @param startpoint The channel that triggered the bufferevent.
 */
void handle_client_connected(socket_ctx* sock_ctx, channel* startpoint) {

    daemon_ctx* daemon = sock_ctx->daemon;
    unsigned long id = sock_ctx->id;
    SSL* ssl = sock_ctx->ssl;

    if (startpoint->bev == sock_ctx->secure.bev) {
        LOG_D("Encrypted client endpoint connected with %s\n", SSL_get_version(ssl));
    } else {
        LOG_W("Unexpected connect event happened for client\n");
        return;
    }

    sock_ctx->state = SOCKET_FINISHING_CONN;

    LOG_D("Client session is %s reused\n", SSL_session_reused(ssl) ? "" : "not");

    if (SSL_session_reused(sock_ctx->ssl) == 0 &&
                has_revocation_checks(sock_ctx->flags))
        do_cert_chain_revocation_checks(sock_ctx);
    else
        netlink_handshake_notify_kernel(daemon, id, NOTIFY_SUCCESS);

    return;
}


/*******************************************************************************
 *                SERVER BUFFEREVENT CALLBACK HELPER FUNCTIONS
 ******************************************************************************/


/**
 * Handles an error event for a server bufferevent and determines whether the
 * daemon should keep the connection alive or close it (designated by 
 * startpoint->closed and endpoint->closed). 
 * @param sock_ctx The context of the socket that received the error.
 * @param error The OpenSSL error that the particular bufferevent encountered.
 * Note that this could be '0', designating no error--either `errno` errors
 * or OpenSSL errors may be present when an error event is received.
 * @param startpoint The channel of the socket that received the error event.
 * @param endpoint The other channel of the socket.
 */
void handle_server_error(socket_ctx* sock_ctx, channel* startpoint) {
    
    unsigned long error = bufferevent_get_openssl_error(startpoint->bev);
    channel* endpoint = (startpoint == &sock_ctx->secure)
                ? &sock_ctx->plain : &sock_ctx->secure;
    daemon_ctx* daemon = sock_ctx->daemon;

    LOG_I("Server %s endpoint encountered error\n",
        (startpoint->bev == sock_ctx->secure.bev) 
                ? "encrypted" : "plaintext");

    /* TODO: errno is unreliable. getsockopt(SO_ERROR) might be better */
    if (errno == ECONNRESET || errno == EPIPE)
        LOG_I("Connection closed by local user\n");
    else if (errno != 0)
        LOG_W("Unhandled error %i has occurred: %s\n", errno, strerror(errno));
    else
        LOG_E("SSL error occurred on endpoint: %s\n", 
                    ERR_reason_error_string(error));


    startpoint->closed = 1;

    if ((evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0)
                && endpoint->closed == 0)
        endpoint->closed = 1;

    if (endpoint->closed == 1) {
        socket_shutdown(sock_ctx);

        if (sock_ctx->state == SOCKET_CONNECTED) {
            LOG_D("Server error socket was SOCKET_CONNECTED\n");
            sock_ctx->state = SOCKET_ERROR;

        } else {
            if (error != 0)
                LOG_E("TLS handshake error %li on incoming connection: %s",
                            error, ERR_error_string(error, NULL));

            LOG_D("Permanently deleting connection\n");
            hashmap_del(daemon->sock_map_port, sock_ctx->local_port);
            socket_context_free(sock_ctx);
        }
    }
}


/**
 * Handles an EOF event by closing both channels in a socket context.
 * @param sock_ctx The context of the socket that received an EOF on
 * one of its bufferevents.
 * @param startpoint The channel of the socket that received the EOF.
 * @param endpoint The other channel of the socket. 
 */
void handle_server_eof(socket_ctx* sock_ctx, channel* startpoint) {

    channel* endpoint = (startpoint == &sock_ctx->secure)
                ? &sock_ctx->plain : &sock_ctx->secure;
    daemon_ctx* daemon = sock_ctx->daemon;
    int is_unclean_shutdown = 0;

    LOG_D("%s server channel got EOF\n", startpoint->bev == sock_ctx->secure.bev 
                ? "encrypted" : "plaintext");


    if (startpoint == &sock_ctx->secure)
        startpoint->closed = 1;

    /* shutdown is unclean if (encrypted) peer closed w/out sending SSL shutdown */
    if (sock_ctx->secure.closed && !sock_ctx->plain.closed
                && !(SSL_get_shutdown(sock_ctx->ssl) & SSL_RECEIVED_SHUTDOWN)) {
        
        LOG_W("TLS shutdown wasn't clean\n");
        is_unclean_shutdown = 1;
    }

    startpoint->closed = 1;

    if (endpoint->closed == 0) {
        if (evbuffer_get_length(bufferevent_get_input(startpoint->bev)) > 0) {
            LOG_D("Channel still had data to be read from it--flushing...\n");
            common_bev_read_cb(endpoint->bev, sock_ctx);
        }

        if (evbuffer_get_length(bufferevent_get_output(endpoint->bev)) == 0)
            endpoint->closed = 1;
    }


    if (endpoint->closed == 1) {
        int free_socket = (sock_ctx->state != SOCKET_CONNECTED) ? 1 : 0;

        if (is_unclean_shutdown)
            sock_ctx->state = SOCKET_DISCONNECTED;

        socket_shutdown(sock_ctx);

        sock_ctx->state = SOCKET_DISCONNECTED;

        if (free_socket) {
            hashmap_del(daemon->sock_map_port, sock_ctx->local_port);
            socket_context_free(sock_ctx);
        }
    }
}


/**
 * Handles the case where one of the server channel's bufferevent connected 
 * successfully. If it's the secure channel, we trigger a connection on the
 * plain channel. If it's the plain channel, we don't do much.
 * @param startpoint The channel that triggered the bufferevent.
 * @returns 0 on success, or -errno if an error occurred.
 */
void handle_server_connected(socket_ctx* sock_ctx, channel* startpoint) {

    LOG_D("%s server endpoint connected\n", startpoint->bev == sock_ctx->secure.bev 
                ? "Encrypted" : "Plaintext");

    if (startpoint->bev == sock_ctx->secure.bev) {
        sock_ctx->state = SOCKET_FINISHING_CONN;

        int ret = bufferevent_enable(sock_ctx->plain.bev, EV_READ | EV_WRITE);
        if (ret != 0)
            goto err;

        ret = bufferevent_socket_connect(sock_ctx->plain.bev, 
                (struct sockaddr*) &sock_ctx->int_addr, sock_ctx->int_addrlen);
        if (ret != 0) {
            LOG_E("Failed to connect to plaintext end: %s\n", strerror(errno));
            goto err;
        }
    }

    return;
err:

    socket_context_erase(sock_ctx, sock_ctx->local_port);
}