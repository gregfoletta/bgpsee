#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "sds.h"
#include "log.h"

#define MAX_LOG_SIZE 4096

enum LOG_LEVEL current_level = LOG_INFO;

sds log_prefix(enum LOG_LEVEL);

void set_log_level(enum LOG_LEVEL level) {
    if (level < LOG_NONE || level > LOG_DEBUG) {
        return;
    }

    current_level = level;

}

void log_print(enum LOG_LEVEL level, const char *format, ... ) {
    va_list args;
    int bytes_would_write;
    sds msg, output;
    //sds prefix = log_prefix(level);

    if (level  > current_level) {
        return;
    }

    msg = sdsnewlen(NULL, MAX_LOG_SIZE);

    va_start(args, format);
    bytes_would_write = vsnprintf(msg, MAX_LOG_SIZE, format, args);
    va_end(args);

    if (bytes_would_write > MAX_LOG_SIZE) {
        log_print(LOG_WARN, "Log message would have written %d bytes, larger than MAX_LOG_SIZE %d\n", bytes_would_write, MAX_LOG_SIZE);
    }

    output = sdscat(log_prefix(level), msg);

    fprintf(stderr, "%s", output);
    //Reset
    fprintf(stderr, "\033[0m");

    sdsfree(output);
    sdsfree(msg);

}

sds log_prefix(enum LOG_LEVEL level) {
    sds prefix;
    time_t now;
    struct tm *tm_info;
    char timestamp[32];

    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S] ", tm_info);

    switch (level) {
        case LOG_NONE:
            prefix = sdsnew(timestamp);
            break;
        case LOG_ERROR:
            //Bold Red
            prefix = sdscatprintf(sdsempty(), "%s\033[1;31m- ", timestamp);
            break;
        case LOG_WARN:
            //Bold Yellow
            prefix = sdscatprintf(sdsempty(), "%s\033[1;33m- ", timestamp);
            break;
        case LOG_INFO:
            //Bold green then reset
            prefix = sdscatprintf(sdsempty(), "%s\033[1;32m- \033[0;m", timestamp);
            break;
        case LOG_DEBUG:
            //Bold Blue then reset
            prefix = sdscatprintf(sdsempty(), "%s\033[1;36m+ \033[0;m", timestamp);
            break;
        default:
            prefix = sdsnew(timestamp);
            break;
    }

    return prefix;
}

