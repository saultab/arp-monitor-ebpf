/* SPDX-License-Identifier: MIT */
/*
 * spoof_detect.c - ARP spoofing detection implementation
 *
 * Simple hash table mapping IP → MAC. When the MAC changes for a known IP,
 * increment a flip counter. Alert when counter exceeds threshold.
 */
#include "spoof_detect.h"
#include <string.h>

static uint32_t hash_ip(uint32_t ip)
{
    /* Simple multiplicative hash */
    return (ip * 2654435761u) % SPOOF_TABLE_SIZE;
}

void spoof_detector_init(struct spoof_detector *sd, uint32_t threshold)
{
    memset(sd, 0, sizeof(*sd));
    sd->threshold = threshold > 0 ? threshold : DEFAULT_SPOOF_THRESHOLD;
}

bool spoof_detector_update(struct spoof_detector *sd, uint32_t ip_net_order, const uint8_t mac[6],
                           uint32_t *flip_count_out)
{
    uint32_t idx = hash_ip(ip_net_order);
    uint32_t start = idx;
    bool spoof_detected = false;

    /* Linear probing */
    do {
        struct mac_entry *e = &sd->entries[idx];

        if (!e->in_use) {
            /* New entry */
            e->in_use = true;
            e->ip = ip_net_order;
            memcpy(e->mac, mac, 6);
            e->flip_count = 0;
            e->first_seen = time(NULL);
            e->last_seen = e->first_seen;
            if (flip_count_out)
                *flip_count_out = 0;
            return false;
        }

        if (e->ip == ip_net_order) {
            /* Existing entry — check if MAC changed */
            e->last_seen = time(NULL);
            if (memcmp(e->mac, mac, 6) != 0) {
                e->flip_count++;
                memcpy(e->mac, mac, 6);
                if (e->flip_count >= sd->threshold) {
                    sd->total_alerts++;
                    spoof_detected = true;
                }
            }
            if (flip_count_out)
                *flip_count_out = e->flip_count;
            return spoof_detected;
        }

        idx = (idx + 1) % SPOOF_TABLE_SIZE;
    } while (idx != start);

    /* Table full — can't insert */
    if (flip_count_out)
        *flip_count_out = 0;
    return false;
}

const struct mac_entry *spoof_detector_lookup(const struct spoof_detector *sd,
                                              uint32_t ip_net_order)
{
    uint32_t idx = hash_ip(ip_net_order);
    uint32_t start = idx;

    do {
        const struct mac_entry *e = &sd->entries[idx];
        if (!e->in_use)
            return NULL;
        if (e->ip == ip_net_order)
            return e;
        idx = (idx + 1) % SPOOF_TABLE_SIZE;
    } while (idx != start);

    return NULL;
}

void spoof_detector_reset(struct spoof_detector *sd)
{
    uint32_t threshold = sd->threshold;
    memset(sd, 0, sizeof(*sd));
    sd->threshold = threshold;
}
