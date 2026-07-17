/* SPDX-License-Identifier: MIT */
/*
 * log.c - Structured logging implementation
 */
#include "log.h"
#include <errno.h>
#include <string.h>

/* Use syslog priority constants with their full names to avoid macro conflicts */
#define SYSLOG_DEBUG   LOG_DEBUG
#define SYSLOG_INFO    LOG_INFO
#define SYSLOG_WARNING LOG_WARNING
#define SYSLOG_ERR     LOG_ERR

static struct log_config g_log = {
    .level = LOG_LVL_INFO,
    .use_syslog = false,
    .file = NULL,
};

static const char *level_str[] = {
    [LOG_LVL_DEBUG] = "DEBUG",
    [LOG_LVL_INFO] = "INFO",
    [LOG_LVL_WARN] = "WARN",
    [LOG_LVL_ERR] = "ERROR",
};

static int level_to_syslog[] = {
    [LOG_LVL_DEBUG] = SYSLOG_DEBUG,
    [LOG_LVL_INFO] = SYSLOG_INFO,
    [LOG_LVL_WARN] = SYSLOG_WARNING,
    [LOG_LVL_ERR] = SYSLOG_ERR,
};

void log_init(struct log_config *cfg)
{
    if (cfg)
        g_log = *cfg;

    if (g_log.use_syslog)
        openlog("arp-monitor", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void log_cleanup(void)
{
    if (g_log.use_syslog)
        closelog();
    if (g_log.file && g_log.file != stderr && g_log.file != stdout)
        fclose(g_log.file);
}

void log_msg(enum log_level level, const char *file, int line, const char *fmt, ...)
{
    if (level < g_log.level)
        return;

    va_list args;
    va_start(args, fmt);

    if (g_log.use_syslog) {
        vsyslog(level_to_syslog[level], fmt, args);
        va_end(args);
        return;
    }

    FILE *out = g_log.file ? g_log.file : stderr;

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(out, "%s.%03ld [%-5s]", timebuf, ts.tv_nsec / 1000000, level_str[level]);

    if (level == LOG_LVL_DEBUG)
        fprintf(out, " %s:%d", file, line);

    fprintf(out, " ");
    vfprintf(out, fmt, args);
    fprintf(out, "\n");
    fflush(out);

    va_end(args);
}
