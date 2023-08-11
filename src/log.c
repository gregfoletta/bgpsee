#include <stdio.h>
#include <stdarg.h>

#include "sds.h"
#include "log.h"

enum LOG_LEVEL current_level = LOG_INFO;

sds log_prefix(enum LOG_LEVEL);

void set_log_level(enum LOG_LEVEL level) {
    if (level < LOG_ERROR || level > LOG_DEBUG) {
        return;
    }

    current_level = level;

}

void log_print(enum LOG_LEVEL level, const char *format, ... ) {
    va_list args;
    sds output;
    //sds prefix = log_prefix(level);

    if (level  > current_level) {
        return;
    }

    va_start(args, format);
    output = sdscatprintf(log_prefix(level), format, args);
    //Add a reset code at the end
    fprintf(stderr, "%s", output);
    va_end(args);
    //Reset
    printf("\033[0m");

    sdsfree(output);

}

sds log_prefix(enum LOG_LEVEL level) {
    sds prefix;

    switch (level) {
        case LOG_ERROR:
            //Bold Red
            prefix = sdsnew("\033[1;31m- ");
            break;
        case LOG_WARN: 
            //Bold Yellow
            prefix = sdsnew("\033[1;33m- ");
            break;
        case LOG_INFO:
            //Bold green then reset
            prefix = sdsnew("\033[1;32m- \033[0;m");
            break;
        case LOG_DEBUG:
            //Bold Blue then reset
            prefix = sdsnew("\033[1;36m- \033[0;m");
            break;
    };

    return prefix;
}

