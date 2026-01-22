#pragma once

#include <sys/timerfd.h>
#include <time.h>
#include <netinet/in.h>


#include "bgp_timers.h"
#include "bgp_print.h"
#include "list.h"
#include "tcp_client.h"
#include "sds.h"


struct bgp_msg;
struct output_queue;

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
    int sent_total;  // Counter for sent messages (used for negative IDs)
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
    uint32_t *local_asn;
    uint32_t peer_asn;
    uint32_t *local_rid;
    uint32_t peer_rid;

    // 4-byte ASN support (RFC 6793)
    int four_octet_asn;  // 1 if both peers support 4-byte ASN

    sds peer_ip;
    sds source_ip;

    pthread_t thread;

    struct bgp_peer_timers peer_timers;
    //Index into the array represents the timer enum ID
    struct bgp_local_timer local_timers[N_LOCAL_TIMERS];

    enum bgp_fsm_states fsm_state;
    unsigned int connect_retry_counter;

    // Reconnection settings
    int reconnect_enabled;              // 0 = disabled (default)
    int reconnect_max_retries;          // 0 = infinite
    uint16_t reconnect_backoff_current; // Current delay in seconds (starts at 5s)
    uint16_t reconnect_backoff_max;     // Cap at 120s
    uint8_t last_notification_code;     // For failure classification
    uint8_t last_notification_subcode;

    struct bgp_socket socket;
    struct bgp_stats stats;

    //Printing
    pthread_mutex_t stdout_lock;
    int (*print_msg)(struct bgp_peer *, struct bgp_msg *);
    enum bgp_output output_format;
    struct output_queue *output_queue;

    //Ingress message queue
    struct list_head ingress_q;
    struct list_head output_q;
};
