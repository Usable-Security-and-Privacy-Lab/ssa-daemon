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

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <event2/util.h>

#include "daemon.h"
#include "log.h"
#include "netlink.h"


// Attributes
enum {
    SSA_NL_A_UNSPEC,
    SSA_NL_A_ID,
    SSA_NL_A_BLOCKING,
    SSA_NL_A_FAMILY,
    SSA_NL_A_SOCKADDR_INTERNAL,
    SSA_NL_A_SOCKADDR_EXTERNAL,
    SSA_NL_A_SOCKADDR_REMOTE,
    SSA_NL_A_OPTLEVEL,
    SSA_NL_A_OPTNAME,
    SSA_NL_A_OPTVAL,
    SSA_NL_A_RETURN,
    SSA_NL_A_PAD,
    __SSA_NL_A_MAX,
};

#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)

// Operations
enum {
    SSA_NL_C_UNSPEC,
    SSA_NL_C_SOCKET_NOTIFY,
    SSA_NL_C_SETSOCKOPT_NOTIFY,
    SSA_NL_C_GETSOCKOPT_NOTIFY,
    SSA_NL_C_BIND_NOTIFY,
    SSA_NL_C_CONNECT_NOTIFY,
    SSA_NL_C_LISTEN_NOTIFY,
    SSA_NL_C_ACCEPT_NOTIFY,
    SSA_NL_C_CLOSE_NOTIFY,
    SSA_NL_C_RETURN,
    SSA_NL_C_LISTEN_ERR,
    SSA_NL_C_DATA_RETURN,
    SSA_NL_C_HANDSHAKE_RETURN,
    __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

// Multicast group
enum ssa_nl_groups {
    SSA_NL_NOTIFY,
};

static struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
    [SSA_NL_A_ID] = { .type = NLA_U64 },
    [SSA_NL_A_BLOCKING] = { .type = NLA_U32 },
    [SSA_NL_A_FAMILY] = { .type = NLA_U16 },
    [SSA_NL_A_SOCKADDR_INTERNAL] = { .type = NLA_BINARY },
    [SSA_NL_A_SOCKADDR_EXTERNAL] = { .type = NLA_BINARY },
    [SSA_NL_A_SOCKADDR_REMOTE] = { .type = NLA_BINARY },
    [SSA_NL_A_OPTLEVEL] = { .type = NLA_U32 },
    [SSA_NL_A_OPTNAME] = { .type = NLA_U32 },
    [SSA_NL_A_OPTVAL] = { .type = NLA_BINARY },
    [SSA_NL_A_RETURN] = { .type = NLA_U32 },
};

int handle_netlink_msg(struct nl_msg* msg, void* arg);

struct nl_sock* netlink_connect(daemon_ctx* ctx) {

    int group;
    int family;
    struct nl_sock* netlink_sock = nl_socket_alloc();
    if (netlink_sock == NULL) {
        LOG_E("Failed to allocate socket\n");
        return NULL;
    }

    nl_socket_set_local_port(netlink_sock, ctx->port);
    nl_socket_disable_seq_check(netlink_sock);
    ctx->netlink_sock = netlink_sock;
    nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, handle_netlink_msg, (void*)ctx);

    if (genl_connect(netlink_sock) != 0) {
        LOG_C("Netlink socket failed to connect--"
                    "another daemon is likely using its port\n");
        errno = 0;
        goto err;
    }

    if ((family = genl_ctrl_resolve(netlink_sock, "SSA")) < 0) {
        LOG_E("Failed to resolve SSA family identifier--"
                "make sure that the SSA kernel module is properly loaded\n");
        errno = 0;
        goto err;
    }
    ctx->netlink_family = family;

    if ((group = genl_ctrl_resolve_grp(netlink_sock, "SSA", "notify")) < 0) {
        LOG_E("Failed to resolve group identifier\n");
        goto err;
    }

    if (nl_socket_add_membership(netlink_sock, group) < 0) {
        LOG_E("Failed to add membership to group\n");
        goto err;
    }

    nl_socket_set_peer_port(netlink_sock, 0);

    return netlink_sock;
err:

    nl_socket_free(netlink_sock);
    return NULL;
}

/**
 * Calls the netlink socket's recv callback method. This callback method
 * is set as handle_netlink_msg when netlink_connect was called, so this
 * function realistically just acts as a wrapper function.
 *
 * When the daemon's event base senses that the netlink socket is ready
 * to read information from, it will call this method (as it was the
 * callback function set in run_daemon when event_new was called for
 * the netlink socket).
 *
 * @see run_daemon in daemon.c
 * @see netlink_connect
 */
void netlink_recv(evutil_socket_t fd, short events, void *arg) {

    struct nl_sock* netlink_sock = (struct nl_sock*)arg;

    /* Receives messages and triggers the set callback (handle_netlink_msg) */
    nl_recvmsgs_default(netlink_sock);

    return;
}

int handle_netlink_msg(struct nl_msg* msg, void* arg) {

    daemon_ctx* ctx = (daemon_ctx*) arg;
    struct nlmsghdr* nlh;
    struct genlmsghdr* gnlh;
    struct nlattr* attrs[SSA_NL_A_MAX + 1];

    unsigned long id;
    unsigned short family;
    int addr_internal_len;
    int addr_external_len;
    int addr_remote_len;
    struct sockaddr_storage addr_internal;
    struct sockaddr_storage addr_external;
    struct sockaddr_storage addr_remote;

    int level;
    int blocking;
    int optname;
    char* optval;
    socklen_t optlen;

    /* Get Message */
    nlh = nlmsg_hdr(msg);
    gnlh = (struct genlmsghdr*) nlmsg_data(nlh);
    int ret = genlmsg_parse(nlh, 0, attrs, SSA_NL_A_MAX, ssa_nl_policy);
    if (ret != 0) {
        LOG_E("Couldn't parse message. Error: %i\n", ret);
        return 0;
    }

    switch (gnlh->cmd) {
    case SSA_NL_C_SOCKET_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        family = nla_get_u16(attrs[SSA_NL_A_FAMILY]);

        socket_cb(ctx, id, family);
        break;

    case SSA_NL_C_SETSOCKOPT_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        log_printf(LOG_INFO, "Received setsockopt notification for socket ID %lu\n", id);
        level = nla_get_u32(attrs[SSA_NL_A_OPTLEVEL]);
        optname = nla_get_u32(attrs[SSA_NL_A_OPTNAME]);
        optlen = nla_len(attrs[SSA_NL_A_OPTVAL]);
        optval = malloc(optlen);
        if (optval == NULL) {
            LOG_E("Failed to allocate optval\n");
            return 1;
        }
        memcpy(optval, nla_data(attrs[SSA_NL_A_OPTVAL]), optlen);
        setsockopt_cb(ctx, id, level, optname, optval, optlen);
        free(optval);
        break;

    case SSA_NL_C_GETSOCKOPT_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        log_printf(LOG_INFO, "Received getsockopt notification for socket ID %lu\n", id);
        level = nla_get_u32(attrs[SSA_NL_A_OPTLEVEL]);
        optname = nla_get_u32(attrs[SSA_NL_A_OPTNAME]);
        getsockopt_cb(ctx, id, level, optname);
        break;

    case SSA_NL_C_BIND_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        addr_internal_len = nla_len(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
        addr_external_len = nla_len(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]);
        memcpy(&addr_internal, nla_data(attrs[SSA_NL_A_SOCKADDR_INTERNAL]), addr_internal_len);
        memcpy(&addr_external, nla_data(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]), addr_external_len);
        log_printf(LOG_INFO, "Received bind notification for socket ID %lu\n", id);
        //log_printf_addr((struct sockaddr*)&addr_internal);
        //log_printf_addr((struct sockaddr*)&addr_external);
        bind_cb(ctx, id, (struct sockaddr*) &addr_internal, addr_internal_len,
                    (struct sockaddr*) &addr_external, addr_external_len);
        break;

    case SSA_NL_C_CONNECT_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        addr_internal_len = nla_len(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
        addr_remote_len = nla_len(attrs[SSA_NL_A_SOCKADDR_REMOTE]);
        memcpy(&addr_internal, nla_data(attrs[SSA_NL_A_SOCKADDR_INTERNAL]), addr_internal_len);
        memcpy(&addr_remote, nla_data(attrs[SSA_NL_A_SOCKADDR_REMOTE]), addr_remote_len);
        blocking = nla_get_u32(attrs[SSA_NL_A_BLOCKING]);

        log_printf(LOG_INFO, "Received connect notification for socket ID %lu\n", id);
       
        
        connect_cb(ctx, id, (struct sockaddr*) &addr_internal, addr_internal_len,
                    (struct sockaddr*) &addr_remote, addr_remote_len, blocking);
        break;

    case SSA_NL_C_LISTEN_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        addr_internal_len = nla_len(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
        addr_external_len = nla_len(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]);
        memcpy(&addr_internal, nla_data(attrs[SSA_NL_A_SOCKADDR_INTERNAL]), addr_internal_len);
        memcpy(&addr_external, nla_data(attrs[SSA_NL_A_SOCKADDR_EXTERNAL]), addr_external_len);
        log_printf(LOG_INFO, "Received listen notification for socket ID %lu\n", id);
        //log_printf_addr((struct sockaddr*)&addr_internal);
        //log_printf_addr((struct sockaddr*)&addr_external);
        listen_cb(ctx, id, (struct sockaddr*) &addr_internal, addr_internal_len,
                    (struct sockaddr*) &addr_external, addr_external_len);
        break;

    case SSA_NL_C_ACCEPT_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        addr_internal_len = nla_len(attrs[SSA_NL_A_SOCKADDR_INTERNAL]);
        memcpy(&addr_internal, nla_data(attrs[SSA_NL_A_SOCKADDR_INTERNAL]), addr_internal_len);
        log_printf(LOG_INFO, "Received accept notification for socket ID %lu\n", id);
        associate_cb(ctx, id, (struct sockaddr*) &addr_internal, addr_internal_len);
        break;

    case SSA_NL_C_CLOSE_NOTIFY:
        id = nla_get_u64(attrs[SSA_NL_A_ID]);
        log_printf(LOG_INFO, "Received close notification for socket ID %lu\n", id);
        close_cb(ctx, id);
        break;

    default:
        LOG_E("unrecognized command\n");
        break;
    }

    return 0;
}

int netlink_disconnect(struct nl_sock* sock) {
        nl_socket_free(sock);
        return 0;
}

void netlink_notify_kernel(daemon_ctx* ctx, unsigned long id, int resp) {
    int ret;
    struct nl_msg* msg;
    void* msg_head;
    int msg_size = NLMSG_HDRLEN + GENL_HDRLEN +
        nla_total_size(sizeof(id)) + nla_total_size(sizeof(resp));
    msg = nlmsg_alloc_size(msg_size);
    if (msg == NULL) {
        LOG_E("Failed to allocate message buffer\n");
        return;
    }
    msg_head = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
            ctx->netlink_family, 0, 0, SSA_NL_C_RETURN, 1);
    if (msg_head == NULL) {
        LOG_E("Failed in genlmsg_put\n");
        return;
    }
    ret = nla_put_u64(msg, SSA_NL_A_ID, id);
    if (ret != 0) {
        LOG_E("Failed to insert ID in netlink msg\n");
        return;
    }
    ret = nla_put_u32(msg, SSA_NL_A_RETURN, resp);
    if (ret != 0) {
        LOG_E("Failed to insert response in netlink msg\n");
        return;
    }
    ret = nl_send_auto(ctx->netlink_sock, msg);
    if (ret < 0) {
        LOG_E("Failed to send netlink msg\n");
        return;
    }
    nlmsg_free(msg);

    return;
}

void netlink_error_notify_kernel(daemon_ctx* ctx, unsigned long id) {
    
    int ret;
    struct nl_msg* msg;
    void* msg_head;
    int msg_size = NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(id));
    msg = nlmsg_alloc_size(msg_size);
    if (msg == NULL) {
        LOG_E("Failed to allocate message buffer\n");
        return;
    }
    msg_head = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
            ctx->netlink_family, 0, 0, SSA_NL_C_LISTEN_ERR, 1);
    if (msg_head == NULL) {
        LOG_E("Failed in genlmsg_put\n");
        return;
    }
    ret = nla_put_u64(msg, SSA_NL_A_ID, id);
    if (ret != 0) {
        LOG_E("Failed to insert ID in netlink msg\n");
        return;
    }
    ret = nl_send_auto(ctx->netlink_sock, msg);
    if (ret < 0) {
        LOG_E("Failed to send netlink msg\n");
        return;
    }
    nlmsg_free(msg);

    return;
}

void netlink_send_and_notify_kernel(daemon_ctx* ctx,
        unsigned long id, const void* data, unsigned int len) {
    int ret;
    struct nl_msg* msg;
    void* msg_head;
    int msg_size = NLMSG_HDRLEN + GENL_HDRLEN +
        nla_total_size(sizeof(id)) + nla_total_size(len);
    msg = nlmsg_alloc_size(msg_size);
    if (msg == NULL) {
        LOG_E("Failed to allocate message buffer\n");
        return;
    }
    msg_head = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
            ctx->netlink_family, 0, 0, SSA_NL_C_DATA_RETURN, 1);
    if (msg_head == NULL) {
        LOG_E("Failed in genlmsg_put\n");
        return;
    }
    ret = nla_put_u64(msg, SSA_NL_A_ID, id);
    if (ret != 0) {
        LOG_E("Failed to insert ID in netlink msg\n");
        return;
    }
    ret = nla_put(msg, SSA_NL_A_OPTVAL, len, data);
    if (ret != 0) {
        LOG_E("Failed to insert data response in netlink msg\n");
        return;
    }
    ret = nl_send_auto(ctx->netlink_sock, msg);
    if (ret < 0) {
        LOG_E("Failed to send netlink msg\n");
        return;
    }
    nlmsg_free(msg);

    return;
}

void netlink_handshake_notify_kernel(daemon_ctx* ctx, unsigned long id, int resp) {
    int ret;
    struct nl_msg* msg;
    void* msg_head;
    int msg_size = NLMSG_HDRLEN + GENL_HDRLEN +
        nla_total_size(sizeof(id)) + nla_total_size(sizeof(resp));
    msg = nlmsg_alloc_size(msg_size);
    if (msg == NULL) {
        LOG_E("Failed to allocate message buffer\n");
        return;
    }
    msg_head = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctx->netlink_family, 0, 0, SSA_NL_C_HANDSHAKE_RETURN, 1);
    if (msg_head == NULL) {
        LOG_E("Failed in genlmsg_put\n");
        return;
    }
    ret = nla_put_u64(msg, SSA_NL_A_ID, id);
    if (ret != 0) {
        LOG_E("Failed to insert ID in netlink msg\n");
        return;
    }
    ret = nla_put_u32(msg, SSA_NL_A_RETURN, resp);
    if (ret != 0) {
        LOG_E("Failed to insert response in netlink msg\n");
        return;
    }
    ret = nl_send_auto(ctx->netlink_sock, msg);
    if (ret < 0) {
        LOG_E("Failed to send netlink msg\n");
        return;
    }
    nlmsg_free(msg);

    return;
}
