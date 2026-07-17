/* SPDX-License-Identifier: MIT */
/*
 * spoof_detect.h - ARP spoofing detection (userspace side)
 */
#ifndef SPOOF_DETECT_H
#define SPOOF_DETECT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define SPOOF_TABLE_SIZE        4096
#define DEFAULT_SPOOF_THRESHOLD 3

struct mac_entry {
    uint8_t mac[6];
    uint32_t flip_count;
    time_t first_seen;
    time_t last_seen;
    bool in_use;
    uint32_t ip; /* network byte order */
};

struct spoof_detector {
    struct mac_entry entries[SPOOF_TABLE_SIZE];
    uint32_t threshold; /* flips before alert */
    uint32_t total_alerts;
};

/* Initialize the spoof detector with a given threshold */
void spoof_detector_init(struct spoof_detector *sd, uint32_t threshold);

/*
 * Update the detector with a new ARP observation.
 * Returns true if spoof is detected (MAC changed for known IP above threshold).
 */
bool spoof_detector_update(struct spoof_detector *sd, uint32_t ip_net_order, const uint8_t mac[6],
                           uint32_t *flip_count_out);

/* Get entry for an IP, or NULL if not tracked */
const struct mac_entry *spoof_detector_lookup(const struct spoof_detector *sd,
                                              uint32_t ip_net_order);

/* Reset all entries */
void spoof_detector_reset(struct spoof_detector *sd);

#endif /* SPOOF_DETECT_H */
