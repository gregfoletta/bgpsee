enum LOG_LEVEL {
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};

void set_log_level(enum LOG_LEVEL);
void log_print(enum LOG_LEVEL, const char *format, ... );

