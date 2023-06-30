#include <sys/timerfd.h>
#include <unistd.h>
#include "bgp_timers.h"

//Entries to be used in bitmask that is returned
#define CONNECT_RETRY_TIMER 1 << ConnectRetryTimer
#define HOLD_TIMER 1 << HoldTimer
#define KEEPALIVE_TIMER 1 << KeepaliveTimer
#define MIN_AS_ORIGIN_TIMER 1 << MinASOriginationIntervalTimer
#define MIN_ROUJTE_ADV_TIMER 1 << MinRouteAdvertisementIntervalTimer
#define DELAY_OPEN_TIMER 1 << DelayOpenTimer
#define IDLE_HOLD_TIMER 1 << IdleHoldTimer

int initialise_local_timers(struct bgp_local_timer *local_timers) {
    //Default seetings according to RFC4271 section 10
    //TODO: have been temporarily changed for testing. Need to reset.
    local_timers[ConnectRetryTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 120 } } };
    //peer->local_timers[HoldTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 90 } } };
    local_timers[HoldTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 30 } } };
    //peer->local_timers[KeepaliveTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 30 } } };
    local_timers[KeepaliveTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 15 } } };
    local_timers[MinASOriginationIntervalTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 15 } } };
    local_timers[MinRouteAdvertisementIntervalTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 30 } } };
    local_timers[DelayOpenTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 0 } } };
    local_timers[IdleHoldTimer] = (struct bgp_local_timer){ .timeout = { .it_value = { .tv_sec = 0 } } };

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

int is_invalid_timer(enum timer timer_id) {
    if (timer_id < 0 || timer_id >= N_LOCAL_TIMERS) { return 1; }
    else { return 0; }
}


int start_timer(struct bgp_local_timer *timers, enum timer timer_id) {
    struct bgp_local_timer *t;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];

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
    t->timeout.it_interval.tv_sec = t->timeout.it_value.tv_sec;

    if( timerfd_settime(t->fd, 0, &t->timeout, NULL) < 0 ) {
        return -1;
    }

    return 0;
}

int disarm_timer(struct bgp_local_timer *timers, enum timer timer_id) { 
    struct bgp_local_timer *t;
    //TODO: confirm passing a stack variable is safe 
    static struct itimerspec disarm_timer = { .it_value = { .tv_sec = 0, }};

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    t = &timers[timer_id];

    if (timerfd_settime(t->fd, 0, &disarm_timer, NULL) < 0) {
        return -1;
    }

    return 0;
}


//Just get the whole number of seconds.
time_t current_timer_value(struct bgp_local_timer *local_timers, enum timer timer_id) {
    struct itimerspec value;

    if (is_invalid_timer(timer_id)) {
        return -1;
    }

    timerfd_gettime(local_timers[timer_id].fd, &value );
    //return local_timers[timer_id].timeout.it_value.tv_sec;
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
        read(timer_fd, &n_fires, sizeof(uint64_t));
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
