/* SPDX-License-Identifier: MIT */
#ifndef ARP_MONITOR_H
#define ARP_MONITOR_H

/*
 * Shared header between BPF (kernel-side) and userspace.
 * Uses __u8/__u16/__u32/__u64 types which are available in both contexts:
 * - BPF: provided by vmlinux.h (included before this header)
 * - Userspace: provided by linux/types.h
 */
#if defined(__bpf__) || defined(__BPF__)
/* vmlinux.h already included before this header — types available */
#else
#include <linux/types.h>
#endif

#define ARP_MONITOR_MAX_ENTRIES  4096
#define ARP_MONITOR_RINGBUF_SIZE (256 * 1024)

/* ARP opcodes (from RFC 826) */
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

/* Event flags */
#define EVENT_FLAG_SPOOF_DETECTED (1 << 0)
#define EVENT_FLAG_NEW_HOST       (1 << 1)
#define EVENT_FLAG_MAC_CHANGED    (1 << 2)

/* Shared event structure sent from BPF program to userspace via ring buffer */
struct arp_event {
    __u16 ar_op;        /* ARP opcode (request/reply)       */
    __u8 ar_sha[6];     /* Sender hardware (MAC) address    */
    __u8 ar_sip[4];     /* Sender IP address                */
    __u8 ar_tha[6];     /* Target hardware (MAC) address    */
    __u8 ar_tip[4];     /* Target IP address                */
    __u32 flags;        /* Event flags (spoof detected etc) */
    __u64 timestamp_ns; /* Kernel timestamp (ktime)         */
} __attribute__((packed));

/* Key for the IP→MAC tracking map (kernel-side) */
struct ip_mac_key {
    __u32 ip; /* IPv4 address in network order    */
} __attribute__((packed));

/* Value for the IP→MAC tracking map (kernel-side) */
struct ip_mac_value {
    __u8 mac[6];        /* Last seen MAC for this IP        */
    __u8 pad[2];        /* Alignment padding                */
    __u32 flip_count;   /* Number of MAC changes observed   */
    __u64 last_seen_ns; /* Last seen timestamp              */
};

#endif /* ARP_MONITOR_H */
