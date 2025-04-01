/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <xdp/xdp_sample.bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,__u64 *timestamp) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 28);
} queue_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

struct metadata {
    __u64 timestamp;
};
SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
    int ret;
    ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(__u64));
    // if (ret)
    // {
    //     bpf_printk("bpf_xdp_adjust_head failed\n");
    //     return XDP_ABORTED;
    // }
    void *data = (void *)(long)ctx->data;//+ sizeof(unsigned long);
    void *data_head = data + 8;
    void *data_end = (void *)(long)ctx->data_end;
    struct metadata *metadata = data;
    if(metadata + 1 > data_end)
        return XDP_ABORTED;
    metadata->timestamp = bpf_ktime_get_tai_ns();
    // ret = bpf_xdp_metadata_rx_timestamp(ctx, &metadata->timestamp);
    // if(ret == -EOPNOTSUPP)
    {
        bpf_printk("timestamp: %llu\n", metadata->timestamp);
    }
    __u32 key = 0;
    __u32 *cnt = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (cnt)
        (*cnt)++;
    __u32* value = bpf_map_lookup_elem(&queue_count_map, &index);
    if (value)
        (*value)++;
        
    // 解析以太网头
    struct ethhdr *eth = data_head;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    // 仅处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 解析 IP 头
    struct iphdr *ip = eth + 1;
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    // 检查源 IP 是否为 192.168.67.129
    if (ip->saddr != bpf_htonl(0xC0A80102))  // 192.168.67.129 的十六进制表示
        return XDP_PASS;
	if (ip->daddr != bpf_htonl(0xC0A80101))  
		return XDP_PASS;	

    // 检查协议是否为 UDP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = ip + 1;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

	if (bpf_map_lookup_elem(&xsks_map, &index))
    {
		return bpf_redirect_map(&xsks_map, index, XDP_PASS);
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";