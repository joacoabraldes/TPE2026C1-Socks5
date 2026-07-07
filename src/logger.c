#include <stdarg.h>
#include <time.h>
#include "logger.h"

static FILE *access_file = NULL;

void logger_init(FILE *access_out) {
    access_file = access_out != NULL ? access_out : stdout;
}

static void iso8601_now(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&t, &tm_buf);
    if (tm == NULL || strftime(buf, n, "%Y-%m-%dT%H:%M:%S%z", tm) == 0) {
        buf[0] = '\0';
    }
}

void logger_access(const char *user, const char *cmd,
                   const char *origin, const char *dest, int status) {
    if (access_file == NULL) {
        access_file = stdout;
    }
    char ts[64];
    iso8601_now(ts, sizeof(ts));
    fprintf(access_file, "%s\t%s\t%s\t%s -> %s\tstatus=%d\n",
            ts,
            user   != NULL ? user   : "-",
            cmd    != NULL ? cmd    : "-",
            origin != NULL ? origin : "-",
            dest   != NULL ? dest   : "-",
            status);
    fflush(access_file);
}

void logger_log(const char *level, const char *fmt, ...) {
    char ts[64];
    iso8601_now(ts, sizeof(ts));
    fprintf(stderr, "%s [%s] ", ts, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
