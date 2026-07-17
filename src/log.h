/* SPDX-License-Identifier: MIT */
/*
 * log.h - Structured logging for arp-monitor
 */
#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>

enum log_level {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO = 1,
    LOG_LVL_WARN = 2,
    LOG_LVL_ERR = 3,
};

struct log_config {
    enum log_level level;
    bool use_syslog;
    FILE *file; /* NULL = stderr */
};

void log_init(struct log_config *cfg);
void log_cleanup(void);
void log_msg(enum log_level level, const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define LOGD(fmt, ...) log_msg(LOG_LVL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) log_msg(LOG_LVL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) log_msg(LOG_LVL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_msg(LOG_LVL_ERR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* LOG_H */
