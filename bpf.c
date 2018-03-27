#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"

#define offsetof __builtin_offsetof
#define htons(x) __constant_htons(x)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

SEC("classifier")
int fixup_ip_checksum(struct __sk_buff *skb)
{
    if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
        return 0;

    // Calculate one's complement sum of IP header except checksum word at
    // offset 24.
    __u64 checksum = 0;
    checksum += load_half(skb, 14);
    checksum += load_word(skb, 16);
    checksum += load_word(skb, 20);
    checksum += load_word(skb, 26);
    checksum += load_word(skb, 30);

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);

    // Write back correct checksum in the packet.
    __u16 checksum16 = htons(~checksum);

    bpf_skb_store_bytes(skb, IP_CSUM_OFF, &checksum16, 2, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
