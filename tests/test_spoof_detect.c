/* SPDX-License-Identifier: MIT */
/*
 * test_spoof_detect.c - Unit tests for ARP spoof detection logic
 *
 * Minimal test framework (no external dependencies).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spoof_detect.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name)                                                                             \
    do {                                                                                           \
        printf("  %-50s", #name);                                                                  \
        tests_run++;                                                                               \
        name();                                                                                    \
        tests_passed++;                                                                            \
        printf(" PASS\n");                                                                         \
    } while (0)

#define ASSERT_TRUE(expr)                                                                          \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            printf(" FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #expr);                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b)    ASSERT_TRUE((a) == (b))

/* ─── Test Cases ──────────────────────────────────────────────────────── */

TEST(test_init)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);
    ASSERT_EQ(sd.threshold, 3u);
    ASSERT_EQ(sd.total_alerts, 0u);
}

TEST(test_new_host_no_spoof)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0; /* 192.168.1.1 in network order */
    uint32_t flips = 99;

    bool result = spoof_detector_update(&sd, ip, mac1, &flips);
    ASSERT_FALSE(result);
    ASSERT_EQ(flips, 0u);
}

TEST(test_same_mac_no_spoof)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0;
    uint32_t flips;

    spoof_detector_update(&sd, ip, mac1, &flips);
    bool result = spoof_detector_update(&sd, ip, mac1, &flips);
    ASSERT_FALSE(result);
    ASSERT_EQ(flips, 0u);
}

TEST(test_mac_change_below_threshold)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint32_t ip = 0x0101A8C0;
    uint32_t flips;

    spoof_detector_update(&sd, ip, mac1, &flips);

    /* First flip (1 < 3 threshold) */
    bool result = spoof_detector_update(&sd, ip, mac2, &flips);
    ASSERT_FALSE(result);
    ASSERT_EQ(flips, 1u);

    /* Second flip (2 < 3 threshold) */
    result = spoof_detector_update(&sd, ip, mac1, &flips);
    ASSERT_FALSE(result);
    ASSERT_EQ(flips, 2u);
}

TEST(test_mac_change_above_threshold)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint32_t ip = 0x0101A8C0;
    uint32_t flips;

    spoof_detector_update(&sd, ip, mac1, &flips); /* insert */
    spoof_detector_update(&sd, ip, mac2, &flips); /* flip 1 */
    spoof_detector_update(&sd, ip, mac1, &flips); /* flip 2 */

    /* Third flip: meets threshold */
    bool result = spoof_detector_update(&sd, ip, mac2, &flips);
    ASSERT_TRUE(result);
    ASSERT_EQ(flips, 3u);
    ASSERT_EQ(sd.total_alerts, 1u);
}

TEST(test_multiple_ips_independent)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 2);

    uint8_t mac1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x01};
    uint8_t mac2[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x02};
    uint32_t ip1 = 0x0101A8C0;
    uint32_t ip2 = 0x0201A8C0;
    uint32_t flips;

    spoof_detector_update(&sd, ip1, mac1, &flips);
    spoof_detector_update(&sd, ip2, mac2, &flips);

    /* Change MAC for ip1 only */
    spoof_detector_update(&sd, ip1, mac2, &flips);
    ASSERT_EQ(flips, 1u);

    /* ip2 unchanged */
    bool result = spoof_detector_update(&sd, ip2, mac2, &flips);
    ASSERT_FALSE(result);
    ASSERT_EQ(flips, 0u);
}

TEST(test_lookup_existing)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    uint32_t ip = 0x0A000001;
    uint32_t flips;

    spoof_detector_update(&sd, ip, mac, &flips);
    const struct mac_entry *entry = spoof_detector_lookup(&sd, ip);
    ASSERT_TRUE(entry != NULL);
    ASSERT_TRUE(memcmp(entry->mac, mac, 6) == 0);
}

TEST(test_lookup_nonexistent)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    const struct mac_entry *entry = spoof_detector_lookup(&sd, 0xDEADBEEF);
    ASSERT_TRUE(entry == NULL);
}

TEST(test_reset)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 5);

    uint8_t mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint32_t ip = 0x01020304;
    uint32_t flips;

    spoof_detector_update(&sd, ip, mac, &flips);
    spoof_detector_reset(&sd);

    const struct mac_entry *entry = spoof_detector_lookup(&sd, ip);
    ASSERT_TRUE(entry == NULL);
    ASSERT_EQ(sd.threshold, 5u);
}

TEST(test_default_threshold)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 0); /* 0 should use default */
    ASSERT_EQ(sd.threshold, (uint32_t)DEFAULT_SPOOF_THRESHOLD);
}

/* ─── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== ARP Spoof Detection Unit Tests ===\n\n");

    RUN_TEST(test_init);
    RUN_TEST(test_new_host_no_spoof);
    RUN_TEST(test_same_mac_no_spoof);
    RUN_TEST(test_mac_change_below_threshold);
    RUN_TEST(test_mac_change_above_threshold);
    RUN_TEST(test_multiple_ips_independent);
    RUN_TEST(test_lookup_existing);
    RUN_TEST(test_lookup_nonexistent);
    RUN_TEST(test_reset);
    RUN_TEST(test_default_threshold);

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
