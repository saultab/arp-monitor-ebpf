#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "ringbuf-reserve-submit.skel.h"
#include "common.h"
#include "if_arp.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static char *opcode_to_text(__u16 opcode)
{
	switch (opcode)
	{
	case ARPOP_REQUEST:
		return "Request";
	case ARPOP_REPLY:
		return "Reply";
	default:
		return "Unknown";
	}
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	char ts[32];
	char filename[32];
	time_t t;

	time(&t);
	struct tm tm = *localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
	strftime(filename, sizeof(ts), "%Y-%m-%d", &tm);
    	strcat(filename, ".txt");

	FILE *fp = fopen(filename, "a");
	if (fp == NULL)
	{
		fprintf(stderr, "Error");
		return -1;
	}

	fprintf(fp, "%-8s\t", ts);
	fprintf(fp, "%s\t\t", opcode_to_text(e->ar_op));
	fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_sha[0], e->ar_sha[1], e->ar_sha[2], e->ar_sha[3], e->ar_sha[4], e->ar_sha[5]);
	fprintf(fp, "%d.%d.%d.%d\t\t", e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3]);
	fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_tha[0], e->ar_tha[1], e->ar_tha[2], e->ar_tha[3], e->ar_tha[4], e->ar_tha[5]);
	fprintf(fp, "%d.%d.%d.%d\n", e->ar_tip[0], e->ar_tip[1], e->ar_tip[2], e->ar_tip[3]);
	fclose(fp);
	
	fprintf(stdout, "%-8s\t", ts);
	fprintf(stdout, "%s\t\t", opcode_to_text(e->ar_op));
	fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_sha[0], e->ar_sha[1], e->ar_sha[2], e->ar_sha[3], e->ar_sha[4], e->ar_sha[5]);
	fprintf(stdout, "%d.%d.%d.%d\t\t", e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3]);
	fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_tha[0], e->ar_tha[1], e->ar_tha[2], e->ar_tha[3], e->ar_tha[4], e->ar_tha[5]);
	fprintf(stdout, "%d.%d.%d.%d\n", e->ar_tip[0], e->ar_tip[1], e->ar_tip[2], e->ar_tip[3]);

	return 0;
}
int main(int argc, char **argv)
{
	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Setup interface */
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return -1;
	}

	unsigned ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0)
	{
		fprintf(stderr, "Unable to find interface %s\n", argv[1]);
		return -1;
	}

	/* Load and verify BPF application */
	struct ringbuf_reserve_submit_bpf *skel = NULL;
	skel = ringbuf_reserve_submit_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Declare two TC hook points, in ingress and egress. libbpf provides
	 * macros to initialize its data structures. The following macros create
	 * two structures of type struct bpf_tc_hook with name tc_hook_ingress
	 * and tc_hook_egress and fields zeroed or initilized with the values we
	 * provide
	 */
	LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);

	/* The next function creates the hook point. TC hook points correspond
	 * to the clsact qdisc (Classify Action Queuing Discipline) of the TC
	 * subsystem. A single qdisc supports programs both in ingress and
	 * egress, so we only need to create it once (e.g., for the ingress)
	 */
	int err = bpf_tc_hook_create(&tc_hook_ingress);
	if (err && err != -EEXIST)
	{
		fprintf(stderr, "Failed to create TC hook: %s\n",
				strerror(errno));
		goto cleanup;
	}

	/* Attach the eBPF program to the TC ingress hook. eBPF programs are
	 * attached in TC mode as ingress or egress classification filters. Each
	 * filter has a unique handle and a priority, which determines the order
	 * of execution in case there are multiple filters attached to the same
	 * side
	 */
	LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1,
				.prog_fd = bpf_program__fd(skel->progs.tc_prog));

	err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
	if (err)
	{
		fprintf(stderr, "Failed to attach TC ingress: %s\n",
				strerror(errno));
		goto cleanup;
	}

	/* Attach the eBPF program to the TC egress hook */
	LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 2, .priority = 1,
				.prog_fd = bpf_program__fd(skel->progs.tc_prog));
	err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
	if (err)
	{
		fprintf(stderr, "Failed to attach TC egress: %s\n",
				strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please Ctrl+C to stop.\n");

	/* Process events */
	printf("%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\n",
		   "TIME", "TYPE", "SENDER MAC", "SENDER IP", "TARGET MAC", "TARGET IP");

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Remove the eBPF filters */
	bpf_tc_hook_destroy(&tc_hook_ingress);
	bpf_tc_hook_destroy(&tc_hook_egress);

	/* Free resources */
	ring_buffer__free(rb);
	ringbuf_reserve_submit_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
