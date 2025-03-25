
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "./common_user_bpf_xdp.h"
#include "./common_params.h"
#include "parse_header.h"
// #include "./common_libbpf.h"
#define NUM_FRAMES         2 * XSK_RING_CONS__DEFAULT_NUM_DESCS
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX
#define ETH_ALEN 6
#define DEST_IP "192.168.1.2"
#define SRC_IP "192.168.1.1"
#define QUEUE_NUM 28

const uint8_t src_mac[ETH_ALEN] = {0x08, 0xc0, 0xeb, 0xa2, 0x81, 0x01}; // 源 MAC 地址 00:0c:29:32:45:e0
const uint8_t dst_mac[ETH_ALEN] = {0x00, 0x77, 0x66, 0x55, 0x44, 0x33}; // 目标 MAC 地址 00:0c:29:39:25:dd
const uint16_t SRC_PORT = 54321;
const uint16_t DEST_PORT = 12345;
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};
struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};
struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx_frames;
	uint32_t unack_seq;
	uint32_t send_seq;
	uint32_t recv_seq;
	struct tcp_int_state istate;
	struct stats_record stats;
	struct stats_record prev_stats;
};

pthread_mutex_t free_mutex;
static struct xdp_program *prog;
struct bpf_program * bpf_prog;
int xsk_map_fd, stat_map_fd, queue_map_fd; // 
bool custom_xsk = false;
struct config cfg = {
	.ifindex   = -1,
};

static const char *__doc__ = "AF_XDP kernel bypass example\n";
uint64_t start_t, end_t;
static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",	 required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static void exit_application(int signal);
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}
static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
		__u32 key = 0;
        __u32 cnt;
        bpf_map_lookup_elem(stat_map_fd, &key, &cnt);
            printf("Packets counted: %u\n", cnt);
		for(int i = 0; i < QUEUE_NUM; i++) {
			__u32 value;
			bpf_map_lookup_elem(queue_map_fd, &i, &value);
			printf("Queue %d: %u\n", i, value);
		}
	}
	return NULL;
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk, int pos)
{
	uint64_t frame;
	pthread_mutex_lock(&free_mutex);
	if (xsk->umem_frame_free == 0)
	{
		printf( pos == 0 ? "recv\n" : "send\n");
		printf("umem_frame_free:%u\n", xsk->umem_frame_free);
		assert(xsk->umem_frame_free > 0);
	}
	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	pthread_mutex_unlock(&free_mutex);
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame, int pos)
{
	pthread_mutex_lock(&free_mutex);
	if(xsk->umem_frame_free >= NUM_FRAMES)
	{
		printf( pos == 0 ? "recv\n" : "send\n");
		printf("umem_frame_free:%u\n", xsk->umem_frame_free);
	}
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
	pthread_mutex_unlock(&free_mutex);
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);	
		if (ret)
			goto error_exit;
	} else {
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info,0);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);
	recvfrom(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx_frames)
		return;

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++),1);

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx_frames -= completed < xsk->outstanding_tx_frames ?
			completed : xsk->outstanding_tx_frames;
	}
}

static bool process_ack(struct xsk_socket_info *xsk)
{
	return true;
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	unsigned long* timestamp = xsk_umem__get_data(xsk->umem->buffer, addr);
	// printf("timestamp:%lu\n", *timestamp);
	struct ethhdr *eth_hdr = (struct ethhdr *)(timestamp + 1);
	struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);
	assert(ip_hdr->protocol == IPPROTO_TCP);
	struct tcphdr *tcp_hdr = (struct tcphdr *)(ip_hdr + 1);
	// if(tcp_hdr->doff != 8)
	// {
	// 	printf("tcp_hdr->doff:%d\n", tcp_hdr->doff);
	// 	printf("tcp_hdr->rst:%d\n", tcp_hdr->rst);
	// 	hex_dump(eth_hdr, len, addr);
	// }
// #define PARSER_TCPINT
#ifdef PARSER_TCPINT
	assert(tcp_hdr->doff == 8);
	struct tcp_int_opt *tcp_int = (struct tcp_int_opt *)(tcp_hdr + 1);
	assert(tcp_int->kind == 0x72);
#endif
	int tx_idx;
	if(tcp_hdr->ack == 0)
	{

		build_eth_header(eth_hdr, src_mac, dst_mac);

		build_ip_header(ip_hdr,ip_hdr->daddr, ip_hdr->saddr, sizeof(struct tcp_int_opt));
		build_tcp_header(tcp_hdr,ntohs(tcp_hdr->dest), ntohs(tcp_hdr->source),ntohl(tcp_hdr->ack_seq), 
			ntohl(tcp_hdr->seq) + ntohs(ip_hdr->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - sizeof(struct tcp_int_opt), true, true);
#ifdef PARSER_TCPINT		
		parser_tcpint_header(tcp_int, &xsk->istate);
		build_tcpint_header(tcp_int, &xsk->istate);
#endif
		while(xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx) < 1);
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = sizeof(struct ethhdr) +  sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcp_int_opt);
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx_frames++;
		xsk->stats.tx_packets++;
		xsk->stats.tx_bytes += xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len;
		xsk->send_seq = ntohl(tcp_hdr->ack_seq);
		return true;
	}
	else{
		// if(ntohl(tcp_hdr->ack_seq) > xsk->send_seq || ntohl(tcp_hdr->ack_seq) < xsk->unack_seq)
		// {
		// 	printf("recv ack_seq:%u, send_seq:%u, unack_seq:%u\n", ntohl(tcp_hdr->ack_seq), xsk->send_seq, xsk->unack_seq);
		// }
		//assert(ntohl(tcp_hdr->ack_seq) <= xsk->send_seq && ntohl(tcp_hdr->ack_seq) >= xsk->unack_seq);
		xsk->recv_seq = ntohl(tcp_hdr->seq);
		process_ack(xsk);
		xsk->unack_seq = ntohl(tcp_hdr->ack_seq);
		return false;
	}
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcv_frames,  i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcv_frames = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcv_frames)
		return;

	bool need_tx = false;
	/* Process received packets */
	for (i = 0; i < rcv_frames; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		need_tx = process_packet(xsk, addr, len);
		if(!need_tx)
			xsk_free_umem_frame(xsk, addr, 0);
		xsk->stats.rx_bytes += len;
	}
	xsk_ring_cons__release(&xsk->rx, rcv_frames);
	xsk->stats.rx_packets += rcv_frames;

	if(need_tx)
	{
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		complete_tx(xsk);
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcv_frames, &idx_fq);
	/* This should not happen, but just in case */
	while (ret != rcv_frames)
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcv_frames, &idx_fq);

	for (i = 0; i < rcv_frames; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk,0);

	xsk_ring_prod__submit(&xsk->umem->fq, rcv_frames);
	recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

static int my_do_unload(struct config* cfg)
{
	char unload_s[256];
	sprintf(unload_s,"bpftool net detach xdp dev %s",cfg->ifname);
	system(unload_s);
	return 0;
}
static void exit_application(int signal)
{
	int err;
	//end_t = gettime();
	printf("start to recycle resourece and exit application...\n");
	cfg.unload_all = true;
	err = my_do_unload(&cfg);
	printf("do_unload return %d\n", err);
	if (err) {
		fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
			cfg.ifname, err);
	}
	global_exit = true;
	//signal = signal;
}

static void tx_and_process(struct config* cfg, struct xsk_socket_info *xsk)
{
    int ret;
	unsigned int completed_frames, stock_frames;
	uint64_t count = 0;
    uint32_t cq_idx = 0,tx_idx = 0;
    char payload[1448];
    memset(payload, 'a', sizeof(payload));
	start_t = gettime();
    while(!global_exit) {
		completed_frames = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &cq_idx);
		for(int i = 0; i < completed_frames; i++)
		{
			// printf("free frame addr:%lu\n", *xsk_ring_cons__comp_addr(&xsk->umem->cq, cq_idx));
			xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq, cq_idx++), 1);
		}
		//释放cq
		xsk_ring_cons__release(&xsk->umem->cq, completed_frames);
		// sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		xsk->outstanding_tx_frames -= completed_frames;
		count += completed_frames;
		//计算可以发送的帧数
		// printf("1:r->cached_cons:%u,r->consumer:%u,r->cached_prod:%u\n", xsk->tx.cached_cons,*(xsk->tx.consumer) ,xsk->tx.cached_prod);
		// stock_frames = xsk_umem_free_frames(xsk) - XSK_RING_PROD__DEFAULT_NUM_DESCS;//xsk_prod_nb_free(&xsk->tx, xsk_umem_free_frames(xsk));//
		// printf("2:r->cached_cons:%u,r->consumer:%u,r->cached_prod:%u\n", xsk->tx.cached_cons,*(xsk->tx.consumer) ,xsk->tx.cached_prod);
		if(xsk->outstanding_tx_frames < XSK_RING_PROD__DEFAULT_NUM_DESCS)
			stock_frames = XSK_RING_PROD__DEFAULT_NUM_DESCS - xsk->outstanding_tx_frames;
		else
			stock_frames = 0;
		if(stock_frames > 0)
		{
        	xsk_ring_prod__reserve(&xsk->tx, stock_frames, &tx_idx);
			// printf("reserve %d frames\n", stock_frames);
		}
		//构建数据包
		for(int i = 0; i < stock_frames; i++)
		{
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = xsk_alloc_umem_frame(xsk,1);
        	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = sizeof(struct ethhdr) + sizeof(struct iphdr) + 
																sizeof(struct tcphdr) + sizeof(struct tcp_int_opt) + sizeof(payload);
			void* pkt = (char *) xsk_umem__get_data(xsk->umem->buffer, xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr);
			struct ethhdr *eth_hdr = (struct ethhdr *) pkt;
			struct iphdr *ip_hdr = (struct iphdr *) (eth_hdr + 1);
			struct tcphdr *tcp_hdr = (struct tcphdr *) (ip_hdr + 1);
			struct tcp_int_opt *tcp_int = (struct tcp_int_opt *) (tcp_hdr + 1);
			build_eth_header(eth_hdr, src_mac, dst_mac);
			build_ip_header(ip_hdr,inet_addr(SRC_IP),inet_addr(DEST_IP), sizeof(struct tcp_int_opt) + sizeof(payload));
			//build_udp_header(udp_hdr, SRC_PORT, DEST_PORT, sizeof(payload));
			build_tcp_header(tcp_hdr, SRC_PORT, DEST_PORT, xsk->send_seq, xsk->recv_seq, true, false);
			build_tcpint_header(tcp_int,&xsk->istate);
			xsk->send_seq += sizeof(payload);
			//memcpy(udp_hdr + 1, payload, sizeof(payload));	
			xsk->stats.tx_packets ++;
			xsk->stats.tx_bytes += xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len;
			tx_idx++;
		}
		//提交数据包
		xsk_ring_prod__submit(&xsk->tx, stock_frames);
			// printf(xsk_ring_prod__needs_wakeup(&xsk->tx) ? "needs wakeup\n" : "no need wakeup\n");
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		xsk->outstanding_tx_frames += stock_frames;

		// printf("this time send %d packets, completed %d packets\n", stock_frames,completed_frames);
		end_t = gettime();
		if(end_t - start_t > 6 * 1e9)
			exit_application(0);	
    }

	double period = (end_t - start_t) / 1000000000.0;
	printf("send %d packets in %f seconds, rate: %f pps, %f mbps\n", count, period, count / period, count * 1460 * 8 / period / 1000000);
}

static void* rx_and_process(void * arg)
{
	struct pollfd fds[2];
	int ret, nfds = 1;
	struct xsk_socket_info *xsk_socket = arg;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (true) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
	return NULL;
}


int main(int argc, char **argv)
{
	int ret;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	pthread_t stats_poll_thread;
	pthread_mutex_init(&free_mutex, NULL);
	int err;
	char errmsg[1024];

	/* Global shutdown handler */
	signal(SIGINT, exit_application);
	struct sigaction sa;
    if (sigaction(SIGINT, NULL, &sa) == -1) {
        perror("sigaction");
        return 1;
    }
	if (sigaction(SIGTERM, NULL, &sa) == -1) {
        perror("sigaction");
        return 1;
    }

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
		struct bpf_map *map;
		custom_xsk = true;
		struct bpf_object* obj = bpf_object__open(cfg.filename);
		bpf_prog = bpf_object__find_program_by_name(obj, cfg.progname);
		bpf_program__set_ifindex(bpf_prog, cfg.ifindex);
		bpf_program__set_flags(bpf_prog, BPF_F_XDP_DEV_BOUND_ONLY);
		err = bpf_object__load(obj);
		if (err) {
			libbpf_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}
		err = bpf_xdp_attach(cfg.ifindex, bpf_program__fd(bpf_prog), XDP_FLAGS_DRV_MODE,NULL);
		if (err) {
			libbpf_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: bpf_xdp_attach: %s\n", errmsg);
			return err;
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(obj, "xsks_map");
		xsk_map_fd = bpf_map__fd(map);
		map = bpf_object__find_map_by_name(obj, "queue_count_map");
		queue_map_fd = bpf_map__fd(map);
		map = bpf_object__find_map_by_name(obj, "xdp_stats_map");
		stat_map_fd = bpf_map__fd(map);
		if (xsk_map_fd < 0){ // || stat_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}
    
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (verbose) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	pthread_t rx_thread;
	pthread_create(&rx_thread, NULL, &rx_and_process, xsk_socket);

	/* Receive and count packets than drop them */
	tx_and_process(&cfg, xsk_socket);
	//rx_and_process(xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);

	return EXIT_OK;
}