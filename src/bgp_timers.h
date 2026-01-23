#pragma once

#include <stdint.h>
#include <time.h>

#include <sys/select.h>


//Names of the timers are taken directly from the RFC
//Hence the naming convention differences
//No timer is used to indicate that no timer has fired.
enum timer {
    ConnectRetryTimer,
    HoldTimer,
    KeepaliveTimer,
    MinASOriginationIntervalTimer,
    MinRouteAdvertisementIntervalTimer,
    DelayOpenTimer,
    IdleHoldTimer,
    N_LOCAL_TIMERS
};


struct bgp_local_timer {
    time_t duration_sec;
    int recurring;
#ifdef __linux__
    struct itimerspec timeout;
    int fd;
#else
    struct timespec expiry;  // absolute time when timer fires (0 = disarmed)
    int armed;
#endif
};

int initialise_local_timers(struct bgp_local_timer *);
int is_invalid_timer(enum timer);
int start_timer(struct bgp_local_timer *, enum timer);
int start_timer_recurring(struct bgp_local_timer *, enum timer);
int disarm_timer(struct bgp_local_timer *, enum timer);
void set_timer_value(struct bgp_local_timer *, enum timer, time_t seconds);
time_t current_timer_value(struct bgp_local_timer *, enum timer);
uint64_t timer_has_fired(struct bgp_local_timer *, enum timer, fd_set *);
int peek_fired_timers(struct bgp_local_timer *, fd_set *);
int which_timer_fired(struct bgp_local_timer *, fd_set *);
