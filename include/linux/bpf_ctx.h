#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/perf_event.h>

#include <net/xdp.h>
#include <net/sock.h>
#include <net/busy_poll.h>
#include <net/sch_generic.h>

#define XDP_BITMAP_SIZE 6
#define PERF_EVENT_BITMAP_SIZE 32
#define SOCKET_FILTER_BITMAP_SIZE 64


void bpf_sync_kernel_ctx(const struct bpf_prog *prog, const void *kernel_ctx, void *bpf_ctx);

