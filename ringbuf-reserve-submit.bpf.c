#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>	/* Definition of valid return codes for eBPF
							  * programs attached to the TC hook
							  * (e.g. TC_ACT_OK)
							  */
#include <bpf/bpf_endian.h> /* Helpers to convert endiannes
							  * (e.g., bpf_ntohs())
							  */
#include <linux/if_ether.h> /* Definition of struct ethhdr */
#include "if_arp.h"			/* Definition of struct arphdr */
#include "common.h"			/* Definition of struct event*/
#include <string.h>

/* BPF ring buffer map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("tc")
int tc_prog(struct __sk_buff *ctx)
{
	/* Retrieve pointers to the begin and end of the packet buffer */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Interpret the first part of the packet as an ethernet header */
	struct ethhdr *eth = data;

	/* Every time we access the packet buffer the eBPF verifier requires us
	 * to explicitly check that the address we are accessing doesn't exceed
	 * the buffer limits
	 */
	if (data + sizeof(*eth) > data_end)
	{
		/* The packet is malformed, the TC_ACT_SHOT return code
		 * instructs the kernel to drop it
		 */
		return TC_ACT_SHOT;
	}

	/* Check if packet is ARP */
	if (eth->h_proto == bpf_ntohs(ETH_P_ARP))
	{
		struct arphdr *arp = (data + sizeof(*eth));

		if (data + sizeof(*eth) + sizeof(*arp) > data_end)
		{
			/* The packet is malformed, the TC_ACT_SHOT return code
			 * instructs the kernel to drop it
			 */
			return TC_ACT_SHOT;
		}

		/* Reserve the packet to the ring buffer */
		struct event *e;
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

		/* Can't happen */
		if (!e)
		{
			return TC_ACT_OK;
		}

		/* Copy fields from packet to the event struct */
		e->ar_op = bpf_ntohs(arp->ar_op);
		memcpy(e->ar_sha, arp->ar_sha, sizeof(e->ar_sha));
		memcpy(e->ar_sip, arp->ar_sip, sizeof(e->ar_sip));
		memcpy(e->ar_tha, arp->ar_tha, sizeof(e->ar_tha));
		memcpy(e->ar_tip, arp->ar_tip, sizeof(e->ar_tip));

		/* Submit the packet to the ring buffer */
		bpf_ringbuf_submit(e, 0);
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";