#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct vxlanhdr {
    __be32 vx_flags;
    __be32 vx_vni;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} allowed_vni_map SEC(".maps");

SEC("xdp")
int filter_vxlan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    if (udph->dest != __constant_htons(4789)) return XDP_PASS;

    struct vxlanhdr *vxh = (void *)(udph + 1);
    if ((void *)(vxh + 1) > data_end) return XDP_PASS;
    if (vxh->vx_flags != __constant_htonl(0x08000000)) return XDP_PASS;

    __u32 vni = __constant_ntohl(vxh->vx_vni) >> 8;
    __u32 *allowed = bpf_map_lookup_elem(&allowed_vni_map, &vni);
    if (!allowed) return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
