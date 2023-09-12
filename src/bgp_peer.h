#pragma once

#include <sys/timerfd.h>
#include <time.h>
#include "bgp_timers.h"
#include "list.h"
#include "tcp_client.h"
#include "sds.h"


struct bgp_msg;

enum bgp_fsm_states { 
    IDLE, 
    CONNECT, 
    ACTIVE, 
    OPENSENT, 
    OPENCONFIRM, 
    ESTABLISHED 
};

struct bgp_socket {
    int fd;
    struct sockaddr_in sock_addr;
};

struct bgp_peer_timers {
    uint16_t conf_hold_time;
    uint16_t recv_hold_time;
    uint16_t *curr_hold_time;
};

/*
 * Each statistic is a 2 element array.
 * * First element: messages sent
 * * Second element: messages received
 */
#define STAT_SENT 0
#define STAT_RECV 1

struct bgp_stats {
    int total;
    int open[2];
    int update[2];
    int notification[2];
    int keepalive[2];
    int route_refresh[2];
};

struct bgp_peer {
    int active;
    sds name;
    unsigned int id;
    uint8_t *version;
    uint16_t *local_asn;
    uint16_t peer_asn;
    uint32_t *local_rid;
    uint32_t peer_rid;

    sds peer_ip;
    sds source_ip;

    pthread_t thread;

    struct bgp_peer_timers peer_timers;
    //Index into the array represents the timer enum ID
    struct bgp_local_timer local_timers[N_LOCAL_TIMERS];

    enum bgp_fsm_states fsm_state;
    unsigned int connect_retry_counter;

    struct bgp_socket socket;
    struct bgp_stats stats;

    //Printing
    pthread_mutex_t stdout_lock;
    void (*print_msg)(struct bgp_msg *);

    //Ingress message queue
    struct list_head ingress_q;
    struct list_head output_q;
};
