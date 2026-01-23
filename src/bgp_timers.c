#include <unistd.h>
#include "bgp_timers.h"

#ifdef __linux__
#include <sys/timerfd.h>
#endif

//Entries to be used in bitmask that is returned
#define CONNECT_RETRY_TIMER 1 << ConnectRetryTimer
#define HOLD_TIMER 1 << HoldTimer
#define KEEPALIVE_TIMER 1 << KeepaliveTimer
#define MIN_AS_ORIGIN_TIMER 1 << MinASOriginationIntervalTimer
#define MIN_ROUJTE_ADV_TIMER 1 << MinRouteAdvertisementIntervalTimer
#define DELAY_OPEN_TIMER 1 << DelayOpenTimer
#define IDLE_HOLD_TIMER 1 << IdleHoldTimer

int is_invalid_timer(enum timer timer_id) {
    if (timer_id < 0 || timer_id >= N_LOCAL_TIMERS) { return 1; }
    else { return 0; }
}


#ifdef __linux__
/* ============================================================
   Linux implementation: timerfd-based timers
   ============================================================ */

int initialise_local_timers(struct bgp_local_timer *local_timers) {
    //Default settings according to RFC4271 section 10
    local_timers[ConnectRetryTimer].duration_sec = 120;
    local_timers[ConnectRetryTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 120 } };

    local_timers[HoldTimer].duration_sec = 30;
    local_timers[HoldTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 30 } };

    local_timers[KeepaliveTimer].duration_sec = 15;
    local_timers[KeepaliveTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 15 } };

    local_timers[MinASOriginationIntervalTimer].duration_sec = 15;
    local_timers[MinASOriginationIntervalTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 15 } };

    local_timers[MinRouteAdvertisementIntervalTimer].duration_sec = 30;
    local_timers[MinRouteAdvertisementIntervalTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 30 } };

    local_timers[DelayOpenTimer].duration_sec = 0;
    local_timers[DelayOpenTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 0 } };

    local_timers[IdleHoldTimer].duration_sec = 0;
    local_timers[IdleHoldTimer].timeout = (struct itimerspec){ .it_value = { .tv_sec = 0 } };

    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        local_timers[timer_id].recurring = 0;
    }

    //Create the FDs. We want the clock to be suspend aware, hence the
    //use of CLOCK_BOOTTIME
    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        local_timers[timer_id].fd = timerfd_create(CLOCK_BOOTTIME, 0);
        if (local_timers[timer_id].fd < 0) {
            return -1;
        }
    }

    return 0;
}

int start_timer(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];
    t->recurring = 0;
    t->timeout.it_interval.tv_sec = 0;
    t->timeout.it_interval.tv_nsec = 0;

    if( timerfd_settime(t->fd, 0, &t->timeout, NULL) < 0 ) {
        return -1;
    }

    return 0;
}

int start_timer_recurring(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    //Add the recurring interval, which will match the initial value
    t = &timers[timer_id];
    t->recurring = 1;
    t->timeout.it_interval.tv_sec = t->timeout.it_value.tv_sec;

    if( timerfd_settime(t->fd, 0, &t->timeout, NULL) < 0 ) {
        return -1;
    }

    return 0;
}

int disarm_timer(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;
    static struct itimerspec disarm_value = { .it_value = { .tv_sec = 0, }};

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];
    t->recurring = 0;

    if (timerfd_settime(t->fd, 0, &disarm_value, NULL) < 0) {
        return -1;
    }

    return 0;
}

void set_timer_value(struct bgp_local_timer *timers, enum timer timer_id, time_t seconds) {
    if (is_invalid_timer(timer_id)) {
        return;
    }

    timers[timer_id].duration_sec = seconds;
    timers[timer_id].timeout.it_value.tv_sec = seconds;
    timers[timer_id].timeout.it_value.tv_nsec = 0;
    timers[timer_id].timeout.it_interval.tv_sec = 0;
    timers[timer_id].timeout.it_interval.tv_nsec = 0;
}


//Just get the whole number of seconds.
time_t current_timer_value(struct bgp_local_timer *local_timers, enum timer timer_id) {
    struct itimerspec value;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    timerfd_gettime(local_timers[timer_id].fd, &value );
    return value.it_value.tv_sec;
}


//This function is used if we want to check if a specific timer has fired
uint64_t timer_has_fired(struct bgp_local_timer *timers, enum timer timer_id, fd_set *set) {
    int timer_fd;
    uint64_t n_fires;

    if (is_invalid_timer(timer_id)) {
        return 0;
    }

    timer_fd = timers[timer_id].fd;

    if ( FD_ISSET(timer_fd, set) ) {
        if (read(timer_fd, &n_fires, sizeof(uint64_t)) < 0) {
            return 0;
        }
        return n_fires;
    }

    return 0;
}

//Returns a bitmask of all the timers that have fired
//doesn't perform a read() on each timer so that the
//timer_has_fired() function can still
int peek_fired_timers(struct bgp_local_timer *timers, fd_set *set) {
    int bitmask = 0;

    for (int x = 0; x < N_LOCAL_TIMERS; x++) {
        if ( FD_ISSET(timers[x].fd, set) ) {
            bitmask |= (1 << x);
        }
    }

    return bitmask;
}


int which_timer_fired(struct bgp_local_timer *timers, fd_set *set) {
    //Find the _FIRST_ timer that fired. Could be more than one. This could be
    //a problem that needs to be fixed down the line

    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        if (FD_ISSET(timers[timer_id].fd, set)) {
            return timer_id;
        }
    }

    return -1;
}

#else
/* ============================================================
   macOS/portable implementation: monotonic clock polling
   ============================================================ */

static void get_monotonic(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

static int timespec_expired(struct timespec *expiry) {
    struct timespec now;
    get_monotonic(&now);
    if (now.tv_sec > expiry->tv_sec) return 1;
    if (now.tv_sec == expiry->tv_sec && now.tv_nsec >= expiry->tv_nsec) return 1;
    return 0;
}

int initialise_local_timers(struct bgp_local_timer *local_timers) {
    //Default settings according to RFC4271 section 10
    local_timers[ConnectRetryTimer].duration_sec = 120;
    local_timers[HoldTimer].duration_sec = 30;
    local_timers[KeepaliveTimer].duration_sec = 15;
    local_timers[MinASOriginationIntervalTimer].duration_sec = 15;
    local_timers[MinRouteAdvertisementIntervalTimer].duration_sec = 30;
    local_timers[DelayOpenTimer].duration_sec = 0;
    local_timers[IdleHoldTimer].duration_sec = 0;

    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        local_timers[timer_id].recurring = 0;
        local_timers[timer_id].armed = 0;
        local_timers[timer_id].expiry.tv_sec = 0;
        local_timers[timer_id].expiry.tv_nsec = 0;
    }

    return 0;
}

int start_timer(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;
    struct timespec now;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];

    if (t->duration_sec == 0) {
        t->armed = 0;
        return 0;
    }

    get_monotonic(&now);
    t->expiry.tv_sec = now.tv_sec + t->duration_sec;
    t->expiry.tv_nsec = now.tv_nsec;
    t->armed = 1;
    t->recurring = 0;

    return 0;
}

int start_timer_recurring(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;
    struct timespec now;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];

    if (t->duration_sec == 0) {
        t->armed = 0;
        return 0;
    }

    get_monotonic(&now);
    t->expiry.tv_sec = now.tv_sec + t->duration_sec;
    t->expiry.tv_nsec = now.tv_nsec;
    t->armed = 1;
    t->recurring = 1;

    return 0;
}

int disarm_timer(struct bgp_local_timer *timers, enum timer timer_id) {
    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    timers[timer_id].armed = 0;
    timers[timer_id].recurring = 0;
    timers[timer_id].expiry.tv_sec = 0;
    timers[timer_id].expiry.tv_nsec = 0;

    return 0;
}

void set_timer_value(struct bgp_local_timer *timers, enum timer timer_id, time_t seconds) {
    if (is_invalid_timer(timer_id)) {
        return;
    }

    timers[timer_id].duration_sec = seconds;
}

time_t current_timer_value(struct bgp_local_timer *local_timers, enum timer timer_id) {
    struct timespec now;
    time_t remaining;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    if (!local_timers[timer_id].armed) {
        return 0;
    }

    get_monotonic(&now);
    remaining = local_timers[timer_id].expiry.tv_sec - now.tv_sec;
    return (remaining > 0) ? remaining : 0;
}

uint64_t timer_has_fired(struct bgp_local_timer *timers, enum timer timer_id, fd_set *set) {
    struct bgp_local_timer *t;
    struct timespec now;
    (void)set;  // fd_set not used in polling implementation

    if (is_invalid_timer(timer_id)) {
        return 0;
    }

    t = &timers[timer_id];

    if (!t->armed) {
        return 0;
    }

    if (!timespec_expired(&t->expiry)) {
        return 0;
    }

    // Timer has fired
    if (t->recurring) {
        // Re-arm for next interval
        get_monotonic(&now);
        t->expiry.tv_sec = now.tv_sec + t->duration_sec;
        t->expiry.tv_nsec = now.tv_nsec;
    } else {
        t->armed = 0;
    }

    return 1;
}

int peek_fired_timers(struct bgp_local_timer *timers, fd_set *set) {
    int bitmask = 0;
    (void)set;  // fd_set not used in polling implementation

    for (int x = 0; x < N_LOCAL_TIMERS; x++) {
        if (timers[x].armed && timespec_expired(&timers[x].expiry)) {
            bitmask |= (1 << x);
        }
    }

    return bitmask;
}

int which_timer_fired(struct bgp_local_timer *timers, fd_set *set) {
    (void)set;  // fd_set not used in polling implementation

    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        if (timers[timer_id].armed && timespec_expired(&timers[timer_id].expiry)) {
            return timer_id;
        }
    }

    return -1;
}

#endif
