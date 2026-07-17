// SPDX-License-Identifier: MIT
/*
 * arp_monitor.c - Userspace component for eBPF ARP monitor
 *
 * Loads the BPF program, attaches to TC hook, polls ring buffer for ARP
 * events, performs spoof detection, and outputs results.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "arp_monitor.skel.h"
#include "arp_monitor.h"
#include "log.h"
#include "spoof_detect.h"

#define PROGRAM_NAME    "arp-monitor"
#define VERSION         "2.0.0"

/* ─── CLI Options ─────────────────────────────────────────────────────── */

struct config {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    bool verbose;
    bool json_output;
    bool daemon_mode;
    uint32_t spoof_threshold;
    char *log_file;
    char *whitelist_file;
};

static struct config g_cfg = {
    .verbose = false,
    .json_output = false,
    .daemon_mode = false,
    .spoof_threshold = DEFAULT_SPOOF_THRESHOLD,
    .log_file = NULL,
    .whitelist_file = NULL,
};

/* ─── Globals ─────────────────────────────────────────────────────────── */

static volatile sig_atomic_t exiting = 0;
static struct spoof_detector g_detector;
static struct arp_monitor_bpf *g_skel = NULL;
static struct ring_buffer *g_rb = NULL;
static struct bpf_tc_hook g_hook_ingress;
static struct bpf_tc_hook g_hook_egress;
static bool g_hooks_created = false;

/* ─── Signal Handling ─────────────────────────────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void setup_signals(void)
{
    struct sigaction sa = {
        .sa_handler = sig_handler,
        .sa_flags = SA_RESETHAND,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ─── libbpf Print Callback ──────────────────────────────────────────── */

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (!g_cfg.verbose && level >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/* ─── Output Formatting ──────────────────────────────────────────────── */

static void format_mac(const uint8_t mac[6], char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ip(const uint8_t ip[4], char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static const char *opcode_str(uint16_t op)
{
    switch (op) {
    case ARP_OP_REQUEST: return "REQUEST";
    case ARP_OP_REPLY:   return "REPLY";
    default:             return "UNKNOWN";
    }
}

static void print_event_text(const struct arp_event *e, bool spoof, uint32_t flips)
{
    char ts[32], smac[18], sip[16], tmac[18], tip[16];
    struct timespec now;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

    format_mac(e->ar_sha, smac, sizeof(smac));
    format_ip(e->ar_sip, sip, sizeof(sip));
    format_mac(e->ar_tha, tmac, sizeof(tmac));
    format_ip(e->ar_tip, tip, sizeof(tip));

    fprintf(stdout, "%-8s  %-7s  %-17s  %-15s  %-17s  %-15s",
            ts, opcode_str(e->ar_op), smac, sip, tmac, tip);

    if (spoof)
        fprintf(stdout, "  [SPOOF ALERT flips=%u]", flips);
    else if (e->flags & EVENT_FLAG_NEW_HOST)
        fprintf(stdout, "  [NEW HOST]");

    fprintf(stdout, "\n");
    fflush(stdout);
}

static void print_event_json(const struct arp_event *e, bool spoof, uint32_t flips)
{
    char smac[18], sip[16], tmac[18], tip[16];
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);
    format_mac(e->ar_sha, smac, sizeof(smac));
    format_ip(e->ar_sip, sip, sizeof(sip));
    format_mac(e->ar_tha, tmac, sizeof(tmac));
    format_ip(e->ar_tip, tip, sizeof(tip));

    fprintf(stdout,
            "{\"timestamp\":%ld.%03ld,"
            "\"opcode\":\"%s\","
            "\"sender_mac\":\"%s\","
            "\"sender_ip\":\"%s\","
            "\"target_mac\":\"%s\","
            "\"target_ip\":\"%s\","
            "\"spoof_detected\":%s,"
            "\"flip_count\":%u,"
            "\"new_host\":%s}\n",
            now.tv_sec, now.tv_nsec / 1000000,
            opcode_str(e->ar_op),
            smac, sip, tmac, tip,
            spoof ? "true" : "false",
            flips,
            (e->flags & EVENT_FLAG_NEW_HOST) ? "true" : "false");
    fflush(stdout);
}

/* ─── Event Handler (ring buffer callback) ────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct arp_event)) {
        LOGW("Received truncated event (%zu < %zu)", data_sz,
                 sizeof(struct arp_event));
        return 0;
    }

    const struct arp_event *e = data;
    uint32_t flip_count = 0;

    /* Userspace spoof detection (mirrors kernel-side, for logging) */
    uint32_t sender_ip;
    memcpy(&sender_ip, e->ar_sip, 4);
    bool spoof = spoof_detector_update(&g_detector, sender_ip,
                                       e->ar_sha, &flip_count);

    if (spoof)
        LOGW("ARP spoof detected: IP %u.%u.%u.%u MAC changed (flips=%u)",
                 e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3],
                 flip_count);

    if (g_cfg.json_output)
        print_event_json(e, spoof, flip_count);
    else
        print_event_text(e, spoof, flip_count);

    return 0;
}

/* ─── CLI Parsing ─────────────────────────────────────────────────────── */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] -i <interface>\n"
        "\n"
        "eBPF-based ARP traffic monitor with spoof detection\n"
        "\n"
        "Options:\n"
        "  -i, --interface <name>   Network interface to monitor (required)\n"
        "  -v, --verbose            Enable verbose/debug output\n"
        "  -j, --json               Output events as JSON (one per line)\n"
        "  -d, --daemon             Run in background (daemon mode)\n"
        "  -t, --threshold <N>      MAC flip threshold for spoof alert (default: %u)\n"
        "  -l, --log-file <path>    Write logs to file instead of stderr\n"
        "  -w, --whitelist <path>   IP-MAC whitelist file (one per line: IP MAC)\n"
        "  -V, --version            Show version and exit\n"
        "  -h, --help               Show this help\n",
        prog, DEFAULT_SPOOF_THRESHOLD);
}

static int parse_args(int argc, char **argv)
{
    static const struct option long_opts[] = {
        {"interface", required_argument, NULL, 'i'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"json",      no_argument,       NULL, 'j'},
        {"daemon",    no_argument,       NULL, 'd'},
        {"threshold", required_argument, NULL, 't'},
        {"log-file",  required_argument, NULL, 'l'},
        {"whitelist", required_argument, NULL, 'w'},
        {"version",   no_argument,       NULL, 'V'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:vjdt:l:w:Vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(g_cfg.ifname, optarg, IFNAMSIZ - 1);
            g_cfg.ifname[IFNAMSIZ - 1] = '\0';
            break;
        case 'v':
            g_cfg.verbose = true;
            break;
        case 'j':
            g_cfg.json_output = true;
            break;
        case 'd':
            g_cfg.daemon_mode = true;
            break;
        case 't': {
            char *endptr = NULL;
            errno = 0;
            long val = strtol(optarg, &endptr, 10);
            if (errno != 0 || endptr == optarg || *endptr != '\0' ||
                val <= 0 || val > 10000) {
                fprintf(stderr, "Invalid threshold: %s (must be integer 1-10000)\n", optarg);
                return -1;
            }
            g_cfg.spoof_threshold = (uint32_t)val;
            break;
        }
        case 'l':
            g_cfg.log_file = optarg;
            break;
        case 'w':
            g_cfg.whitelist_file = optarg;
            break;
        case 'V':
            printf("%s version %s\n", PROGRAM_NAME, VERSION);
            exit(0);
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (g_cfg.ifname[0] == '\0') {
        fprintf(stderr, "Error: interface name is required (-i <name>)\n");
        print_usage(argv[0]);
        return -1;
    }

    g_cfg.ifindex = if_nametoindex(g_cfg.ifname);
    if (g_cfg.ifindex == 0) {
        fprintf(stderr, "Error: interface '%s' not found: %s\n",
                g_cfg.ifname, strerror(errno));
        return -1;
    }

    return 0;
}

/* ─── Daemonize ───────────────────────────────────────────────────────── */

static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        exit(0);  /* Parent exits */

    if (setsid() < 0)
        return -1;

    /* Redirect stdin/stdout/stderr to /dev/null */
    if (!freopen("/dev/null", "r", stdin))
        return -1;
    if (!freopen("/dev/null", "w", stdout))
        return -1;
    /* stderr handled by log system */

    umask(0027);
    return 0;
}

/* ─── Cleanup ─────────────────────────────────────────────────────────── */

static void cleanup(void)
{
    LOGI("Shutting down...");

    if (g_rb) {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }

    if (g_hooks_created) {
        bpf_tc_hook_destroy(&g_hook_ingress);
        bpf_tc_hook_destroy(&g_hook_egress);
        g_hooks_created = false;
        LOGD("TC hooks destroyed");
    }

    if (g_skel) {
        arp_monitor_bpf__destroy(g_skel);
        g_skel = NULL;
        LOGD("BPF skeleton destroyed");
    }

    log_cleanup();
}

/* ─── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int err = 0;

    /* Parse CLI */
    if (parse_args(argc, argv) != 0)
        return 1;

    /* Initialize logging */
    struct log_config log_cfg = {
        .level = g_cfg.verbose ? LOG_LVL_DEBUG : LOG_LVL_INFO,
        .use_syslog = g_cfg.daemon_mode,
        .file = NULL,
    };
    if (g_cfg.log_file) {
        log_cfg.file = fopen(g_cfg.log_file, "a");
        if (!log_cfg.file) {
            fprintf(stderr, "Cannot open log file '%s': %s\n",
                    g_cfg.log_file, strerror(errno));
            return 1;
        }
    }
    log_init(&log_cfg);

    /* Daemon mode */
    if (g_cfg.daemon_mode) {
        if (daemonize() != 0) {
            LOGE("Failed to daemonize: %s", strerror(errno));
            return 1;
        }
    }

    /* Setup signal handlers */
    setup_signals();

    /* Initialize spoof detector */
    spoof_detector_init(&g_detector, g_cfg.spoof_threshold);

    LOGI("Starting %s v%s on interface %s (idx=%u, threshold=%u)",
             PROGRAM_NAME, VERSION, g_cfg.ifname, g_cfg.ifindex,
             g_cfg.spoof_threshold);

    /* Set libbpf print callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open and load BPF program */
    g_skel = arp_monitor_bpf__open_and_load();
    if (!g_skel) {
        LOGE("Failed to open/load BPF skeleton: %s", strerror(errno));
        err = 1;
        goto out;
    }
    LOGD("BPF program loaded successfully");

    /* Create TC hooks */
    memset(&g_hook_ingress, 0, sizeof(g_hook_ingress));
    g_hook_ingress.sz = sizeof(g_hook_ingress);
    g_hook_ingress.ifindex = g_cfg.ifindex;
    g_hook_ingress.attach_point = BPF_TC_INGRESS;

    memset(&g_hook_egress, 0, sizeof(g_hook_egress));
    g_hook_egress.sz = sizeof(g_hook_egress);
    g_hook_egress.ifindex = g_cfg.ifindex;
    g_hook_egress.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&g_hook_ingress);
    if (err && err != -EEXIST) {
        LOGE("Failed to create TC ingress hook: %s", strerror(-err));
        err = 1;
        goto out;
    }
    g_hooks_created = true;
    LOGD("TC ingress hook created");

    /* Attach BPF program to ingress */
    LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress,
                .handle = 1, .priority = 1,
                .prog_fd = bpf_program__fd(g_skel->progs.arp_monitor));
    err = bpf_tc_attach(&g_hook_ingress, &tc_opts_ingress);
    if (err == -EEXIST) {
        /* Stale filter from previous unclean exit — detach and retry */
        LOGW("Stale TC ingress filter detected, replacing...");
        tc_opts_ingress.flags = BPF_TC_F_REPLACE;
        err = bpf_tc_attach(&g_hook_ingress, &tc_opts_ingress);
    }
    if (err) {
        LOGE("Failed to attach TC ingress: %s", strerror(-err));
        err = 1;
        goto out;
    }
    LOGD("BPF program attached to TC ingress");

    /* Attach BPF program to egress */
    LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress,
                .handle = 2, .priority = 1,
                .prog_fd = bpf_program__fd(g_skel->progs.arp_monitor));
    err = bpf_tc_attach(&g_hook_egress, &tc_opts_egress);
    if (err == -EEXIST) {
        LOGW("Stale TC egress filter detected, replacing...");
        tc_opts_egress.flags = BPF_TC_F_REPLACE;
        err = bpf_tc_attach(&g_hook_egress, &tc_opts_egress);
    }
    if (err) {
        LOGE("Failed to attach TC egress: %s", strerror(-err));
        err = 1;
        goto out;
    }
    LOGD("BPF program attached to TC egress");

    /* Set up ring buffer polling */
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events),
                            handle_event, NULL, NULL);
    if (!g_rb) {
        LOGE("Failed to create ring buffer: %s", strerror(errno));
        err = 1;
        goto out;
    }

    /* Print header (text mode only) */
    if (!g_cfg.json_output) {
        printf("%-8s  %-7s  %-17s  %-15s  %-17s  %-15s  %s\n",
               "TIME", "TYPE", "SENDER MAC", "SENDER IP",
               "TARGET MAC", "TARGET IP", "FLAGS");
        printf("─────────────────────────────────────────────────────"
               "───────────────────────────────────────────────────\n");
    }

    LOGI("Monitoring started. Press Ctrl+C to stop.");

    /* Event loop */
    while (!exiting) {
        err = ring_buffer__poll(g_rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            LOGE("Error polling ring buffer: %s", strerror(-err));
            break;
        }
    }

out:
    cleanup();
    return err != 0 ? 1 : 0;
}
