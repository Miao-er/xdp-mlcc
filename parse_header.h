#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include "checksum.h"
// 构建以太网帧

struct uint24 {
    unsigned u24 : 24;
} __attribute__((packed));

struct tcp_int_opt {
    uint8_t kind;
    uint8_t len;
    uint32_t linkspeed : 4;
    uint32_t tagfreqkey : 4;
    uint8_t intval;
    uint8_t id;
    struct uint24 hoplat;
    uint8_t intvalecr;
    unsigned linkspeedecr : 4;
    unsigned idecr : 4;
    uint16_t hoplatecr;
} __attribute__((packed));

struct tcp_int_state
{
    bool pending_ecr;         /* Indicates pending echo request */
    uint8_t intvalecr;    /* INT value to be echoed back (network order) */
    uint8_t idecr;         /* ID to be echoed back (network order) */
    uint32_t qdepth;             /* Queue depth in data path */
    uint16_t hoplatecr; /* Sum of hop latencies on data path */
    uint8_t linkspeedecr;
    uint32_t util;
};

#define TCP_INT_UTIL_BITSHIFT 3
#define TCP_INT_QDEPTH_BITSHIFT 13
#define TCP_INT_HLAT_BITSHIFT 8
#define TCP_INT_MIN_AVAILBW_SCALED 0x7f
#define TCP_INT_MIN_QDEPTH_SCALED 0x80
#define TCP_INT_TTL_INIT 64

#define tcp_int_id_to_idecr(x) (TCP_INT_TTL_INIT - (x))

#define tcp_int_hoplat_to_hoplatecr(x)                                         \
    (((x)&0xff8000) ? (((x) >> TCP_INT_HLAT_BITSHIFT) | 0x8000) : (x))

#define tcp_int_id_to_idecr(x) (TCP_INT_TTL_INIT - (x))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be24tohl(x) (bpf_ntohl((x) << 8))
#else
#define be24tohl(x) (x)
#endif

static inline bool tcp_int_ival_is_qdepth(uint8_t ival)
{
    return (ival >= TCP_INT_MIN_QDEPTH_SCALED);
}

static inline uint32_t tcp_int_ival_to_qdepth_scaled(uint8_t ival)
{
    return tcp_int_ival_is_qdepth(ival) ? (ival & TCP_INT_MIN_AVAILBW_SCALED)
                                        : 0;
}

static inline uint32_t tcp_int_ival_to_qdepth(uint8_t ival)
{
    return tcp_int_ival_to_qdepth_scaled(ival) << TCP_INT_QDEPTH_BITSHIFT;
}

static inline __u32 tcp_int_ival_to_util(uint8_t ival)
{
    return tcp_int_ival_is_qdepth(ival) ? 100 : (ival << TCP_INT_UTIL_BITSHIFT);
}

void build_eth_header(struct ethhdr *eth, const uint8_t *src_mac, const uint8_t *dst_mac) {
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);
}

// 构建 IP 头
void build_ip_header(struct iphdr *ip, uint32_t src_ip, uint32_t dst_ip, uint16_t payload_len) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0; // 校验和由内核计算
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
	ip->check = ip_fast_csum((const void *)ip, ip->ihl);
}

// 构建 UDP 头
void build_udp_header(struct udphdr *udp, uint16_t src_port, uint16_t dst_port, uint16_t payload_len) {
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0; // 校验和可选
}

void build_tcp_header(struct tcphdr* tcp, uint16_t src_port, uint16_t dst_port,uint32_t seq, uint32_t ack_seq, bool tcp_int, bool ack)
{
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack_seq);
    tcp->doff = tcp_int ? 8 : 5;
    tcp->res1 = 0;
    tcp->cwr = 0;
    tcp->ece = 0;
    tcp->urg = 0;
    tcp->ack = ack;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = htons(2048);
    tcp->check = 0;
    tcp->urg_ptr = 0;
}

void build_tcpint_header(struct tcp_int_opt* tcp_int,  const struct tcp_int_state* istate)
{
    memset(tcp_int, 0, sizeof(struct tcp_int_opt));
    tcp_int->kind = 0x72;
    tcp_int->len = 12;
    tcp_int->tagfreqkey = 0xf;
    tcp_int->intvalecr = istate->intvalecr;
    tcp_int->linkspeedecr = istate->linkspeedecr;
    tcp_int->idecr = istate->idecr; 
    tcp_int->hoplatecr = istate->hoplatecr;
}

void parser_tcpint_header(struct tcp_int_opt* iopt, struct tcp_int_state* istate)
{
    if (iopt->id) {
        istate->intvalecr = iopt->intval;
        istate->idecr = tcp_int_id_to_idecr(iopt->id);
        istate->hoplatecr =
            tcp_int_hoplat_to_hoplatecr(be24tohl(iopt->hoplat.u24));
        istate->linkspeedecr = iopt->linkspeed;
        istate->pending_ecr = true;
    }

    /* Ignore local events with no updates */
    if (iopt->idecr == 0) {
        return;
    }

    istate->qdepth = tcp_int_ival_to_qdepth(iopt->intvalecr);
    istate->util = tcp_int_ival_to_util(iopt->intvalecr);
}
static void hex_dump(void *pkt, size_t length, uint64_t addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}