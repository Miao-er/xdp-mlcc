/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

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

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 key = 0;
    __u32 *cnt = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (cnt)
        (*cnt)++;
    __u32* value = bpf_map_lookup_elem(&queue_count_map, &index);
    if (value)
        (*value)++;
        
    // 解析以太网头
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // 仅处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 解析 IP 头
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // 检查源 IP 是否为 192.168.67.129
    if (ip->saddr != bpf_htonl(0xC0A80102))  // 192.168.67.129 的十六进制表示
        return XDP_PASS;
	if (ip->daddr != bpf_htonl(0xC0A80101))  
		return XDP_PASS;	

    // 检查协议是否为 UDP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // else
    // {
    //     __u32 new_one = 1;
    //     bpf_map_update_elem(&queue_count_map, &index, &new_one, BPF_ANY);
    // }
	if (bpf_map_lookup_elem(&xsks_map, &index))
    {
		return bpf_redirect_map(&xsks_map, index, XDP_PASS);
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";