// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * arp_monitor.bpf.c - eBPF program for ARP traffic monitoring
 *
 * Attaches to TC (clsact qdisc) hook to intercept ARP packets.
 * Extracts ARP fields and forwards events to userspace via ring buffer.
 * Maintains an IP→MAC hash map for kernel-side spoof detection.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Include shared definitions */
#include "arp_monitor.h"

/* TC return codes (not provided by vmlinux.h) */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* ETH_P_ARP is 0x0806 */
#define ETH_P_ARP 0x0806

/* Ethernet header length */
#define ETH_HLEN 14

/* Minimal ARP header for IPv4 over Ethernet */
struct arp_hdr {
    __be16 ar_hrd;  /* Hardware type */
    __be16 ar_pro;  /* Protocol type */
    __u8 ar_hln;    /* Hardware address length */
    __u8 ar_pln;    /* Protocol address length */
    __be16 ar_op;   /* ARP opcode */
    __u8 ar_sha[6]; /* Sender hardware address */
    __u8 ar_sip[4]; /* Sender protocol address */
    __u8 ar_tha[6]; /* Target hardware address */
    __u8 ar_tip[4]; /* Target protocol address */
} __attribute__((packed));

/* Ring buffer map for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, ARP_MONITOR_RINGBUF_SIZE);
} events SEC(".maps");

/* Hash map: IP → MAC tracking for spoof detection (kernel-side) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARP_MONITOR_MAX_ENTRIES);
    __type(key, struct ip_mac_key);
    __type(value, struct ip_mac_value);
} ip_mac_map SEC(".maps");

/* Configurable spoof detection threshold (can be set from userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} arp_config SEC(".maps");

static __always_inline int mac_equal(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] &&
           a[5] == b[5];
}

static __always_inline __u32 ip_from_bytes(const __u8 *ip)
{
    return (__u32)ip[0] | (__u32)ip[1] << 8 | (__u32)ip[2] << 16 | (__u32)ip[3] << 24;
}

SEC("tc")
int arp_monitor(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Bounds check: Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Only process ARP packets */
    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return TC_ACT_OK;

    /* Bounds check: ARP header */
    struct arp_hdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return TC_ACT_OK;

    /* Only handle IPv4 over Ethernet ARP (hrd=1, pro=0x0800, hln=6, pln=4) */
    if (arp->ar_hln != 6 || arp->ar_pln != 4)
        return TC_ACT_OK;

    /* Prepare event */
    struct arp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->ar_op = bpf_ntohs(arp->ar_op);
    __builtin_memcpy(e->ar_sha, arp->ar_sha, 6);
    __builtin_memcpy(e->ar_sip, arp->ar_sip, 4);
    __builtin_memcpy(e->ar_tha, arp->ar_tha, 6);
    __builtin_memcpy(e->ar_tip, arp->ar_tip, 4);
    e->timestamp_ns = bpf_ktime_get_ns();
    e->flags = 0;

    /* Spoof detection: check if MAC changed for this IP */
    struct ip_mac_key key = {.ip = ip_from_bytes(arp->ar_sip)};
    struct ip_mac_value *existing = bpf_map_lookup_elem(&ip_mac_map, &key);

    if (existing) {
        if (!mac_equal(existing->mac, arp->ar_sha)) {
            /* MAC changed for this IP — potential spoof */
            __sync_fetch_and_add(&existing->flip_count, 1);
            e->flags |= EVENT_FLAG_SPOOF_DETECTED | EVENT_FLAG_MAC_CHANGED;

            /* Update stored MAC */
            __builtin_memcpy(existing->mac, arp->ar_sha, 6);
            existing->last_seen_ns = e->timestamp_ns;
        } else {
            existing->last_seen_ns = e->timestamp_ns;
        }
    } else {
        /* New host seen */
        struct ip_mac_value new_val = {};
        __builtin_memcpy(new_val.mac, arp->ar_sha, 6);
        new_val.flip_count = 0;
        new_val.last_seen_ns = e->timestamp_ns;
        bpf_map_update_elem(&ip_mac_map, &key, &new_val, BPF_ANY);
        e->flags |= EVENT_FLAG_NEW_HOST;
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
