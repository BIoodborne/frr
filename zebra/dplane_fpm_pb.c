/*
 * Zebra dataplane plugin for Forwarding Plane Manager (FPM) using protocol
 * buffer.
 */

#include "config.h"
#include "lib/zebra.h"
#include "lib/libfrr.h"
#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"

#define SOUTHBOUND_DEFAULT_PORT 2620
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
	

} *gfpc;

enum fpm_pb_events {
	/* Ask for FPM to reconnect the external server. */
	FNE_RECONNECT,
	/* Disable FPM. */
	FNE_DISABLE,	
};

static void fpm_reconnect(struct fpm_pb_ctx *fpc);
static int fpm_connect(struct event *t);


static void fpm_process_event(struct event *t)
{
	struct fpm_pb_ctx *fpc = EVENT_ARG(t);
	enum fpm_pb_events event = EVENT_VAL(t);

	switch (event) {
	case FNE_DISABLE:
		zlog_info("%s: manual FPM disable event", __func__);
		fpc->disabled = true;
		// atomic_fetch_add_explicit(&fpc->counters.user_disables, 1,
		// 			  memory_order_relaxed);

		/* Call reconnect to disable timers and clean up context. */
		fpm_reconnect(fpc);
		break;

	case FNE_RECONNECT:
		zlog_info("%s: manual FPM reconnect event", __func__);
		fpc->disabled = false;
		// atomic_fetch_add_explicit(&fpc->counters.user_configures, 1,
		// 			  memory_order_relaxed);
		fpm_reconnect(fpc);
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
	// event_add_write(fpc->fthread->master, fpm_write, fpc, sock,
	// 		&fpc->t_write);
	zlog_info("fpm_pb connect success\n");
}

static int fpm_pb_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	int counter, limit;


	limit = dplane_provider_get_work_limit(prov);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane provider '%s': processing",
			   dplane_provider_get_name(prov));
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;


		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}


	if (counter >= limit) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug(
				"dplane provider '%s' reached max updates %d",
				dplane_provider_get_name(prov), counter);
		dplane_provider_work_ready();
	}
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
	// fpc->disabled = true;
	fpc->prov = prov;
	dplane_ctx_q_init(&fpc->ctxqueue);
	pthread_mutex_init(&fpc->ctxqueue_mutex, NULL);
	// fpc->use_nhg = true;

	struct sockaddr_in *sin;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (inet_pton(AF_INET, "127.0.0.1", naddr) != 1) {
		zlog_warn("Invalid address: %s\n", "127.0.0.1");
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

static int fpm_pb_new(struct event_loop *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	int rv;

	rv = dplane_provider_register(prov_name, DPLANE_PRIO_POSTPROCESS,
				      DPLANE_PROV_FLAG_THREADED, fpm_pb_start,
				      fpm_pr_process, NULL, NULL, &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);
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
		 .init = fpm_pr_init, );