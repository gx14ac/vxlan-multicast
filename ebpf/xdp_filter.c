typedef unsigned short __sum16;
typedef unsigned int   __wsum;
typedef unsigned int   __be32;
typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;

#define ETH_P_IP     0x0800
#define IPPROTO_UDP  17  // ← 明示的に定義（linux/in.h は使わない）

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int vxlan_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udph = (void*)((void*)iph + iph->ihl * 4);
    if ((void*)(udph + 1) > data_end) return XDP_PASS;
    if (udph->dest != __builtin_bswap16(4789)) return XDP_PASS;

    unsigned char *vxh = (unsigned char*)(udph + 1);
    if (vxh + 8 > (unsigned char*)data_end) return XDP_PASS;

    int vni = vxh[4] << 16 | vxh[5] << 8 | vxh[6];
    if (vni != 100) return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";