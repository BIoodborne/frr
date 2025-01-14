// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for Forwarding Plane Manager (FPM) using protocol
 * buffer.
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */


#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>

#include "lib/zebra.h"
#include "lib/json.h"
#include "lib/libfrr.h"
#include "lib/frratomic.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_router.h"
#include "zebra/interface.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/debug.h"
#include "fpm/fpm.h"

#include "qpb/qpb.pb-c.h"
#include "qpb/qpb.h"
#include "qpb/qpb_allocator.h"
#include "qpb/linear_allocator.h"
#include "fpm/fpm_pb.h"

#define SOUTHBOUND_DEFAULT_ADDR INADDR_LOOPBACK
#define SOUTHBOUND_DEFAULT_PORT 2620
#define FPM_HEADER_SIZE 4
static const char *prov_name = "dplane_fpm_pb";

struct fpm_pb_ctx {
	int socket;
	bool connecting;
	bool disabled;
	struct sockaddr_storage addr;
	struct zebra_dplane_provider *prov;
	/* data plane buffers. */
	struct stream *ibuf;
	struct stream *obuf;
	pthread_mutex_t obuf_mutex;

	struct dplane_ctx_list_head ctxqueue;
	pthread_mutex_t ctxqueue_mutex;

	struct frr_pthread *fthread;

	struct event *t_connect;
	struct event *t_read;
	struct event *t_write;
	struct event *t_event;
	struct event *t_dequeue;
	/* Statistic counters. */
	struct {
		/* Amount of bytes read into ibuf. */
		_Atomic uint32_t bytes_read;
		/* Amount of bytes written from obuf. */
		_Atomic uint32_t bytes_sent;
		/* Output buffer current usage. */
		_Atomic uint32_t obuf_bytes;
		/* Output buffer peak usage. */
		_Atomic uint32_t obuf_peak;

		/* Amount of connection closes. */
		_Atomic uint32_t connection_closes;
		/* Amount of connection errors. */
		_Atomic uint32_t connection_errors;

		/* Amount of user configurations: FNE_RECONNECT. */
		_Atomic uint32_t user_configures;
		/* Amount of user disable requests: FNE_DISABLE. */
		_Atomic uint32_t user_disables;

		/* Amount of data plane context processed. */
		_Atomic uint32_t dplane_contexts;
		/* Amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len;
		/* Peak amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len_peak;

		/* Amount of buffer full events. */
		_Atomic uint32_t buffer_full;
	} counters;


} * gfpc;

enum fpm_pb_events {
	/* Ask for FPM to reconnect the external server. */
	FNE_RECONNECT,
	/* Disable FPM. */
	FNE_DISABLE,
	/* Reconnect request by our own code to avoid races. */
	FNE_INTERNAL_RECONNECT,
	/* Reset counters. */
	FNE_RESET_COUNTERS,
};

#define FPM_RECONNECT(fpc)                                                     \
	event_add_event((fpc)->fthread->master, fpm_process_event, (fpc),      \
			FNE_INTERNAL_RECONNECT, &(fpc)->t_event)

#define WALK_FINISH(fpc, ev)                                                   \
	event_add_event((fpc)->fthread->master, fpm_process_event, (fpc),      \
			(ev), NULL)

/*
 * Prototypes.
 */
static void fpm_reconnect(struct fpm_pb_ctx *fpc);
static int fpm_connect(struct event *t);
static void fpm_process_event(struct event *t);
static void fpm_process_queue(struct event *t);
static int fpm_pb_process(struct zebra_dplane_provider *prov);
static ssize_t protobuf_msg_encode(struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen);
static int fpm_pb_enqueue(struct fpm_pb_ctx *fpc, struct zebra_dplane_ctx *ctx);
static Fpm__Message *create_route_message(qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx);
static Fpm__AddRoute *create_add_route_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx);

/*
 * CLI.
 */
#define FPM_STR "Forwarding Plane Manager configuration\n"

DEFUN(fpm_set_address, fpm_set_address_cmd,
      "fpm address <A.B.C.D|X:X::X:X> [port (1-65535)]",
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (argc == 5)
		port = strtol(argv[4]->arg, NULL, 10);

	/* Handle IPv4 addresses. */
	if (inet_pton(AF_INET, argv[2]->arg, naddr) == 1) {
		sin = (struct sockaddr_in *)&gfpc->addr;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port =
			port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		memcpy(&sin->sin_addr, naddr, sizeof(sin->sin_addr));

		goto ask_reconnect;
	}

	/* Handle IPv6 addresses. */
	if (inet_pton(AF_INET6, argv[2]->arg, naddr) != 1) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING;
	}

	sin6 = (struct sockaddr_in6 *)&gfpc->addr;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin6->sin6_addr, naddr, sizeof(sin6->sin6_addr));

ask_reconnect:
	event_add_event(gfpc->fthread->master, fpm_process_event, gfpc,
			FNE_RECONNECT, &gfpc->t_event);
	return CMD_SUCCESS;
}

DEFUN(no_fpm_set_address, no_fpm_set_address_cmd,
      "no fpm address [<A.B.C.D|X:X::X:X> [port <1-65535>]]",
      NO_STR FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	event_add_event(gfpc->fthread->master, fpm_process_event, gfpc,
			FNE_DISABLE, &gfpc->t_event);
	return CMD_SUCCESS;
}


DEFUN(fpm_show_counters, fpm_show_counters_cmd, "show fpm counters",
      SHOW_STR FPM_STR "FPM statistic counters\n")
{
	vty_out(vty, "%30s\n%30s\n", "FPM counters", "============");

#define SHOW_COUNTER(label, counter)                                           \
	vty_out(vty, "%28s: %u\n", (label), (counter))

	SHOW_COUNTER("Input bytes", gfpc->counters.bytes_read);
	SHOW_COUNTER("Output bytes", gfpc->counters.bytes_sent);
	SHOW_COUNTER("Output buffer current size", gfpc->counters.obuf_bytes);
	SHOW_COUNTER("Output buffer peak size", gfpc->counters.obuf_peak);
	SHOW_COUNTER("Connection closes", gfpc->counters.connection_closes);
	SHOW_COUNTER("Connection errors", gfpc->counters.connection_errors);
	SHOW_COUNTER("Data plane items processed",
		     gfpc->counters.dplane_contexts);
	SHOW_COUNTER("Data plane items enqueued", gfpc->counters.ctxqueue_len);
	SHOW_COUNTER("Data plane items queue peak",
		     gfpc->counters.ctxqueue_len_peak);
	SHOW_COUNTER("Buffer full hits", gfpc->counters.buffer_full);
	SHOW_COUNTER("User FPM configurations", gfpc->counters.user_configures);
	SHOW_COUNTER("User FPM disable requests", gfpc->counters.user_disables);

#undef SHOW_COUNTER

	return CMD_SUCCESS;
}

DEFUN(fpm_reset_counters, fpm_reset_counters_cmd, "clear fpm counters",
      CLEAR_STR FPM_STR "FPM statistic counters\n")
{
	event_add_event(gfpc->fthread->master, fpm_process_event, gfpc,
			FNE_RESET_COUNTERS, &gfpc->t_event);
	return CMD_SUCCESS;
}

static int fpm_write_config(struct vty *vty)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int written = 0;

	if (gfpc->disabled)
		return written;

	switch (gfpc->addr.ss_family) {
	case AF_INET:
		written = 1;
		sin = (struct sockaddr_in *)&gfpc->addr;
		vty_out(vty, "fpm address %pI4", &sin->sin_addr);
		if (sin->sin_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin->sin_port));

		vty_out(vty, "\n");
		break;
	case AF_INET6:
		written = 1;
		sin6 = (struct sockaddr_in6 *)&gfpc->addr;
		vty_out(vty, "fpm address %pI6", &sin6->sin6_addr);
		if (sin6->sin6_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin6->sin6_port));

		vty_out(vty, "\n");
		break;

	default:
		break;
	}

	return written;
}

static struct cmd_node fpm_node = {
	.name = "fpm",
	.node = FPM_NODE,
	.prompt = "",
	.config_write = fpm_write_config,
};


static void fpm_write(struct event *t)
{
	struct fpm_pb_ctx *fpc = EVENT_ARG(t);
	socklen_t statuslen;
	ssize_t bwritten;
	int rv, status;
	size_t btotal;

	if (fpc->connecting == true) {
		status = 0;
		statuslen = sizeof(status);

		rv = getsockopt(fpc->socket, SOL_SOCKET, SO_ERROR, &status,
				&statuslen);
		if (rv == -1 || status != 0) {
			if (rv != -1)
				zlog_warn("%s: connection failed: %s", __func__,
					  strerror(status));
			else
				zlog_warn("%s: SO_ERROR failed: %s", __func__,
					  strerror(status));


			FPM_RECONNECT(fpc);
			return;
		}

		fpc->connecting = false;

		/* Permit receiving messages now. */
		// event_add_read(fpc->fthread->master, fpm_read, fpc,
		// fpc->socket, 	       &fpc->t_read);
	}

	frr_mutex_lock_autounlock(&fpc->obuf_mutex);

	while (true) {
		/* Stream is empty: reset pointers and return. */
		if (STREAM_READABLE(fpc->obuf) == 0) {
			stream_reset(fpc->obuf);
			break;
		}

		/* Try to write all at once. */
		btotal =
			stream_get_endp(fpc->obuf) - stream_get_getp(fpc->obuf);
		bwritten = write(fpc->socket, stream_pnt(fpc->obuf), btotal);
		if (bwritten == 0) {
			atomic_fetch_add_explicit(
				&fpc->counters.connection_closes, 1,
				memory_order_relaxed);

			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: connection closed", __func__);
			break;
		}
		if (bwritten == -1) {
			/* Attempt to continue if blocked by a signal. */
			if (errno == EINTR)
				continue;
			/* Receiver is probably slow, lets give it some time. */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			atomic_fetch_add_explicit(
				&fpc->counters.connection_errors, 1,
				memory_order_relaxed);
			zlog_warn("%s: connection failure: %s", __func__,
				  strerror(errno));

			FPM_RECONNECT(fpc);
			return;
		}

		/* Account all bytes sent. */
		atomic_fetch_add_explicit(&fpc->counters.bytes_sent, bwritten,
					  memory_order_relaxed);

		// /* Account number of bytes free. */
		atomic_fetch_sub_explicit(&fpc->counters.obuf_bytes, bwritten,
					  memory_order_relaxed);

		stream_forward_getp(fpc->obuf, (size_t)bwritten);
	}

	/* Stream is not empty yet, we must schedule more writes. */
	if (STREAM_READABLE(fpc->obuf)) {
		stream_pulldown(fpc->obuf);
		event_add_write(fpc->fthread->master, fpm_write, fpc,
				fpc->socket, &fpc->t_write);
		return;
	}
}

static void fpm_process_event(struct event *t)
{
	struct fpm_pb_ctx *fpc = EVENT_ARG(t);
	enum fpm_pb_events event = EVENT_VAL(t);

	switch (event) {
	case FNE_DISABLE:
		zlog_info("%s: manual FPM disable event", __func__);
		fpc->disabled = true;
		atomic_fetch_add_explicit(&fpc->counters.user_disables, 1,
					  memory_order_relaxed);

		/* Call reconnect to disable timers and clean up context. */
		fpm_reconnect(fpc);
		break;

	case FNE_RECONNECT:
		zlog_info("%s: manual FPM reconnect event", __func__);
		fpc->disabled = false;
		atomic_fetch_add_explicit(&fpc->counters.user_configures, 1,
					  memory_order_relaxed);
		fpm_reconnect(fpc);
		break;
	case FNE_INTERNAL_RECONNECT:
		fpm_reconnect(fpc);
		break;
	case FNE_RESET_COUNTERS:
		zlog_info("%s: manual FPM counters reset event", __func__);
		memset(&fpc->counters, 0, sizeof(fpc->counters));
		break;
	}
}

static void fpm_reconnect(struct fpm_pb_ctx *fpc)
{
	/*
	 * Grab the lock to empty the streams (data plane might try to
	 * enqueue updates while we are closing).
	 */
	frr_mutex_lock_autounlock(&fpc->obuf_mutex);

	/* Avoid calling close on `-1`. */
	if (fpc->socket != -1) {
		close(fpc->socket);
		fpc->socket = -1;
	}

	stream_reset(fpc->ibuf);
	stream_reset(fpc->obuf);
	EVENT_OFF(fpc->t_read);
	EVENT_OFF(fpc->t_write);

	/* FPM is disabled, don't attempt to connect. */
	if (fpc->disabled)
		return;

	event_add_timer(fpc->fthread->master, fpm_connect, fpc, 3,
			&fpc->t_connect);
}

static int fpm_connect(struct event *t)
{
	struct fpm_pb_ctx *fpc = EVENT_ARG(t);
	struct sockaddr_in *sin = (struct sockaddr_in *)&fpc->addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fpc->addr;
	socklen_t slen;
	int rv, sock;
	char addrstr[INET6_ADDRSTRLEN];

	sock = socket(fpc->addr.ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: fpm socket failed: %s", __func__,
			 strerror(errno));
		event_add_timer(fpc->fthread->master, fpm_connect, fpc, 3,
				&fpc->t_connect);
		return;
	}

	set_nonblocking(sock);

	if (fpc->addr.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin);
	} else {
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin6);
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: attempting to connect to %s:%d", __func__,
			   addrstr, ntohs(sin->sin_port));

	rv = connect(sock, (struct sockaddr *)&fpc->addr, slen);
	if (rv == -1 && errno != EINPROGRESS) {
		atomic_fetch_add_explicit(&fpc->counters.connection_errors, 1,
					  memory_order_relaxed);
		close(sock);
		zlog_warn("%s: fpm connection failed: %s", __func__,
			  strerror(errno));
		event_add_timer(fpc->fthread->master, fpm_connect, fpc, 3,
				&fpc->t_connect);
		return;
	}

	fpc->connecting = (errno == EINPROGRESS);
	fpc->socket = sock;
	// if (!fpc->connecting)
	// 	event_add_read(fpc->fthread->master, fpm_read, fpc, sock,
	// 		       &fpc->t_read);
	zlog_info("[fpm_connect] start fpm write");
	event_add_write(fpc->fthread->master, fpm_write, fpc, sock,
			&fpc->t_write);
}

static int fpm_pb_process(struct zebra_dplane_provider *prov)
{
	zlog_info("[fpm_pb_process] start");
	struct zebra_dplane_ctx *ctx;
	struct fpm_pb_ctx *fpc;
	int counter, limit;
	uint64_t cur_queue, peak_queue = 0, stored_peak_queue;

	fpc = dplane_provider_get_data(prov);
	limit = dplane_provider_get_work_limit(prov);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane provider '%s': processing",
			   dplane_provider_get_name(prov));
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;

		/*
		 * Skip all notifications if not connected, we'll walk the RIB
		 * anyway.
		 */
		zlog_info("[fpm_pb_process] socket is %d,connecting is %d",
			  fpc->socket, fpc->connecting);
		if (fpc->socket != -1 && fpc->connecting == false) {

			/*
			 * Update the number of queued contexts *before*
			 * enqueueing, to ensure counter consistency.
			 */
			atomic_fetch_add_explicit(&fpc->counters.ctxqueue_len,
						  1, memory_order_relaxed);

			frr_with_mutex (&fpc->ctxqueue_mutex) {
				dplane_ctx_enqueue_tail(&fpc->ctxqueue, ctx);
			}

			cur_queue = atomic_load_explicit(
				&fpc->counters.ctxqueue_len,
				memory_order_relaxed);
			if (peak_queue < cur_queue)
				peak_queue = cur_queue;
			continue;
		}


		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}
	/* Update peak queue length, if we just observed a new peak */
	stored_peak_queue = atomic_load_explicit(
		&fpc->counters.ctxqueue_len_peak, memory_order_relaxed);
	if (stored_peak_queue < peak_queue)
		atomic_store_explicit(&fpc->counters.ctxqueue_len_peak,
				      peak_queue, memory_order_relaxed);

	if (atomic_load_explicit(&fpc->counters.ctxqueue_len,
				 memory_order_relaxed) > 0)
		event_add_timer(fpc->fthread->master, fpm_process_queue, fpc, 0,
				&fpc->t_dequeue);

	if (counter >= limit) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug(
				"dplane provider '%s' reached max updates %d",
				dplane_provider_get_name(prov), counter);
		dplane_provider_work_ready();
	}
}

static void fpm_process_queue(struct event *t)
{
	struct fpm_pb_ctx *fpc = EVENT_ARG(t);
	struct zebra_dplane_ctx *ctx;
	bool no_bufs = false;
	uint64_t processed_contexts = 0;

	while (true) {
		/* No space available yet. */
		if (STREAM_WRITEABLE(fpc->obuf) < NL_PKT_BUF_SIZE) {
			no_bufs = true;
			break;
		}

		/* Dequeue next item or quit processing. */
		frr_with_mutex (&fpc->ctxqueue_mutex) {
			ctx = dplane_ctx_dequeue(&fpc->ctxqueue);
		}
		if (ctx == NULL)
			break;

		/*
		 * Intentionally ignoring the return value
		 * as that we are ensuring that we can write to
		 * the output data in the STREAM_WRITEABLE
		 * check above, so we can ignore the return
		 */
		if (fpc->socket != -1)
			(void)fpm_pb_enqueue(fpc, ctx);

		/* Account the processed entries. */
		processed_contexts++;
		atomic_fetch_sub_explicit(&fpc->counters.ctxqueue_len, 1,
					  memory_order_relaxed);

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(fpc->prov, ctx);
	}

	/* Update count of processed contexts */
	atomic_fetch_add_explicit(&fpc->counters.dplane_contexts,
				  processed_contexts, memory_order_relaxed);

	/* Re-schedule if we ran out of buffer space */
	if (no_bufs)
		event_add_timer(fpc->fthread->master, fpm_process_queue, fpc, 0,
				&fpc->t_dequeue);

	/*
	 * Let the dataplane thread know if there are items in the
	 * output queue to be processed. Otherwise they may sit
	 * until the dataplane thread gets scheduled for new,
	 * unrelated work.
	 */
	if (dplane_provider_out_ctx_queue_len(fpc->prov) > 0)
		dplane_provider_work_ready();
}

static Fpm__Message *create_route_message(qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx)
{
	Fpm__Message *msg;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg) {
		return NULL;
	}

	fpm__message__init(msg);
	switch (op) {
	case DPLANE_OP_ROUTE_INSTALL:
		/*create add route message*/
		msg->has_type = 1;
		msg->type = FPM__MESSAGE__TYPE__ADD_ROUTE;
		if (IS_ZEBRA_DEBUG_FPM) {
			zlog_debug("fpm_pb message:");
			zlog_debug("==========");
			zlog_debug("has_type: %d", msg->has_type);
			zlog_debug("type: %d", msg->type);
		}
		msg->add_route = create_add_route_message(allocator, ctx);
		if (!msg->add_route) {
			return NULL;
		}
		break;

	/* Un-handled by FPM at this time. */
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
	case DPLANE_OP_NONE:
		break;
	}

	return msg;
}

static Fpm__AddRoute *create_add_route_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx)
{
	Fpm__AddRoute *msg;
	struct nexthop *nexthop;
	const struct prefix *p;
	uint num_nhs, u;
	struct nexthop *nexthops[MULTIPATH_NUM];

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg)
		return NULL;

	p = dplane_ctx_get_dest(ctx);
	if (!p)
		return NULL;

	fpm__add_route__init(msg);
	msg->vrf_id = dplane_ctx_get_vrf(ctx);
	msg->address_family = p->family;
	msg->metric = dplane_ctx_get_metric(ctx);
	/*
	 * XXX Hardcode subaddress family for now.
	 */
	msg->sub_address_family = QPB__SUB_ADDRESS_FAMILY__UNICAST;
	msg->key = fpm_route_key_create(allocator, p);
	msg->has_route_type = 1;
	msg->route_type = FPM__ROUTE_TYPE__NORMAL;

	if (IS_ZEBRA_DEBUG_FPM) {
		zlog_debug("add route message:");
		zlog_debug("==========");
		zlog_debug("vrf_id: %d", msg->vrf_id);
		zlog_debug("address_family: %d", msg->address_family);
		zlog_debug("metric:%d", msg->metric);
		zlog_debug("sub_address_family: %d", msg->sub_address_family);
		zlog_debug("has_router_type: %d", msg->has_route_type);
		zlog_debug("route_type:%d", msg->route_type);
	}
	return msg;
}

static ssize_t protobuf_msg_encode(struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen)
{
	zlog_info("[protobuf_msg_encode] start");
	Fpm__Message *msg;
	QPB_DECLARE_STACK_ALLOCATOR(allocator, 4096);
	size_t len;

	QPB_INIT_STACK_ALLOCATOR(allocator);

	msg = create_route_message(&allocator, ctx);
	if (!msg) {
		return 0;
	}
	len = fpm__message__pack(msg, data);
	/* not enough space */
	if (len > datalen) {
		return 0;
	}
	QPB_RESET_STACK_ALLOCATOR(allocator);
	return len;
}

static int fpm_pb_enqueue(struct fpm_pb_ctx *fpc, struct zebra_dplane_ctx *ctx)
{
	zlog_info("[fpm_pb_enqueue] start");
	uint8_t pb_buf[NL_PKT_BUF_SIZE];
	size_t pb_buf_len;
	ssize_t rv;
	uint64_t obytes, obytes_peak;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	pb_buf_len = 0;
	frr_mutex_lock_autounlock(&fpc->obuf_mutex);

	pb_buf_len = protobuf_msg_encode(ctx, pb_buf, sizeof(pb_buf));

	if (pb_buf_len == 0) {
		/* protobuf msg encode error */
		return 0;
	}


	/* We must know if someday a message goes beyond 65KiB. */
	assert((pb_buf_len + FPM_HEADER_SIZE) <= UINT16_MAX);

	/* Check if we have enough buffer space. */
	if (STREAM_WRITEABLE(fpc->obuf) < (pb_buf_len + FPM_HEADER_SIZE)) {
		atomic_fetch_add_explicit(&fpc->counters.buffer_full, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug(
				"%s: buffer full: wants to write %zu but has %zu",
				__func__, pb_buf_len + FPM_HEADER_SIZE,
				STREAM_WRITEABLE(fpc->obuf));

		return -1;
	}

	/*
	 * Fill in the FPM header information.
	 *
	 * See FPM_HEADER_SIZE definition for more information.
	 */
	stream_putc(fpc->obuf, 1);
	stream_putc(fpc->obuf, 2);
	stream_putw(fpc->obuf, pb_buf_len + FPM_HEADER_SIZE);

	/* Write current data. */
	stream_write(fpc->obuf, pb_buf, (size_t)pb_buf_len);

	/* Account number of bytes waiting to be written. */
	atomic_fetch_add_explicit(&fpc->counters.obuf_bytes,
				  pb_buf_len + FPM_HEADER_SIZE,
				  memory_order_relaxed);
	obytes = atomic_load_explicit(&fpc->counters.obuf_bytes,
				      memory_order_relaxed);
	obytes_peak = atomic_load_explicit(&fpc->counters.obuf_peak,
					   memory_order_relaxed);
	if (obytes_peak < obytes)
		atomic_store_explicit(&fpc->counters.obuf_peak, obytes,
				      memory_order_relaxed);

	/* Tell the thread to start writing. */
	event_add_write(fpc->fthread->master, fpm_write, fpc, fpc->socket,
			&fpc->t_write);

	return 0;
}

static int fpm_pb_start(struct zebra_dplane_provider *prov)
{
	struct fpm_pb_ctx *fpc;

	fpc = dplane_provider_get_data(prov);
	fpc->fthread = frr_pthread_new(NULL, prov_name, prov_name);
	assert(frr_pthread_run(fpc->fthread, NULL) == 0);
	fpc->ibuf = stream_new(NL_PKT_BUF_SIZE);
	fpc->obuf = stream_new(NL_PKT_BUF_SIZE * 128);
	pthread_mutex_init(&fpc->obuf_mutex, NULL);
	fpc->socket = -1;
	fpc->disabled = true;
	fpc->prov = prov;
	dplane_ctx_q_init(&fpc->ctxqueue);
	pthread_mutex_init(&fpc->ctxqueue_mutex, NULL);

	struct sockaddr_in *sin;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (inet_pton(AF_INET, "127.0.0.1", naddr) != 1) {
		zlog_warn("Invalid address: %s", "127.0.0.1");
		return -1;
	}

	sin = (struct sockaddr_in *)&gfpc->addr;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(SOUTHBOUND_DEFAULT_PORT);
	memcpy(&sin->sin_addr, naddr, sizeof(sin->sin_addr));

	event_add_event(gfpc->fthread->master, fpm_process_event, gfpc,
			FNE_RECONNECT, &gfpc->t_event);

	return 0;
}

static int fpm_pb_finish_early(struct fpm_pb_ctx *fpc)
{
	/* Disable all events and close socket. */
	EVENT_OFF(fpc->t_event);
	event_cancel_async(fpc->fthread->master, &fpc->t_read, NULL);
	event_cancel_async(fpc->fthread->master, &fpc->t_write, NULL);
	event_cancel_async(fpc->fthread->master, &fpc->t_connect, NULL);

	if (fpc->socket != -1) {
		close(fpc->socket);
		fpc->socket = -1;
	}

	return 0;
}

static int fpm_pb_finish_late(struct fpm_pb_ctx *fpc)
{
	/* Stop the running thread. */
	frr_pthread_stop(fpc->fthread, NULL);

	/* Free all allocated resources. */
	pthread_mutex_destroy(&fpc->obuf_mutex);
	pthread_mutex_destroy(&fpc->ctxqueue_mutex);
	stream_free(fpc->ibuf);
	stream_free(fpc->obuf);
	free(gfpc);
	gfpc = NULL;

	return 0;
}

static int fpm_pb_finish(struct zebra_dplane_provider *prov, bool early)
{
	struct fpm_pb_ctx *fpc;

	fpc = dplane_provider_get_data(prov);
	if (early)
		return fpm_pb_finish_early(fpc);

	return fpm_pb_finish_late(fpc);
}

static int fpm_pb_new(struct event_loop *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	int rv;
	gfpc = calloc(1, sizeof(*gfpc));
	rv = dplane_provider_register(
		prov_name, DPLANE_PRIO_POSTPROCESS, DPLANE_PROV_FLAG_THREADED,
		fpm_pb_start, fpm_pb_process, fpm_pb_finish, gfpc, &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);

	install_node(&fpm_node);
	install_element(ENABLE_NODE, &fpm_show_counters_cmd);
	install_element(ENABLE_NODE, &fpm_reset_counters_cmd);
	install_element(CONFIG_NODE, &fpm_set_address_cmd);
	install_element(CONFIG_NODE, &no_fpm_set_address_cmd);
	return 0;
}

static int fpm_pb_init(void)
{
	hook_register(frr_late_init, fpm_pb_new);
	return 0;
}

FRR_MODULE_SETUP(.name = "dplane_fpm_pb", .version = "0.0.1",
		 .description =
			 "Data plane plugin for FPM using protocol buffer.",
		 .init = fpm_pb_init, );
