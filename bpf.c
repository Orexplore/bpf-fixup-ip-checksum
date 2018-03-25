#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"

#define offsetof __builtin_offsetof

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

SEC("classifier")
int fixup_ip_checksum(struct __sk_buff *skb)
{
    if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
        return 0;

    __u16 checksum = 0;
    for (int i = 0; i < sizeof(struct iphdr); i += 2) {
        checksum += ~load_half(skb, ETH_HLEN + i);
    }
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, 0xffff, checksum, 2);

    return 0;
}

char _license[] SEC("license") = "GPL";
