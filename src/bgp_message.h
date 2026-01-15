#pragma once 

#include <stdint.h>
#include <sys/types.h>

#include "list.h"

// Max IPv4 CIDR string: "255.255.255.255/32" (18 chars) + null
#define MAX_IPV4_ROUTE_STRING 20

enum bgp_msg_type {
    OPEN = 1,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE,
    ROUTE_REFRESH,
    NUMBER_OF_MSG_TYPES //This will evaluate to the number msg types. Used during validation.
};

//OPEN message
struct bgp_open {
    uint8_t version;
    uint16_t asn;
    uint16_t hold_time;
    uint32_t router_id;
    uint8_t opt_param_len;
    struct bgp_msg_open_param *opt_params;
};

/*
 UPDATE message and its dependencies
 https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
*/

struct path_segment {
    uint8_t type;
    uint8_t n_as;
    uint16_t *as;
    struct list_head list;
};

struct as_path {
    int n_segments;
    int n_total_as;
    struct list_head segments;
};

struct aggregator {
    uint16_t asn;
    uint32_t ip;
};

struct bgp_path_attribute {
    uint8_t flags;
    uint8_t type;
    //16 bits covers standard and extended length;
    uint16_t length;
    union {
        uint8_t origin;
        struct as_path *as_path;
        uint32_t next_hop;
        uint32_t multi_exit_disc;
        uint32_t local_pref;
        //Atomic aggregate is length zero, defined only by the type
        struct aggregator *aggregator;
    }; 
};

/* 
 * Length is in in bits (as per the length field in the NLRI information
 * But we add in bytes (which isn't in the BGP UPDATE). Bytes must be between
 * 0 and 4 inclusive.
*/


struct ipv4_nlri {
    uint8_t length;
    uint8_t bytes;
    uint8_t prefix[4];
    struct list_head list;
    char string[MAX_IPV4_ROUTE_STRING];
};

/*
 * Path attributes index by their value, running from 0-255
 * https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
 * 
 */

enum bgp_update_attrs {
    ORIGIN = 1,
    AS_PATH,
    NEXT_HOP,
    MULTI_EXIT_DISC,
    LOCAL_PREF,
    ATOMIC_AGGREGATE,
    AGGREGATOR
};

#define MAX_ATTRIBUTE 255

struct bgp_update {
    //Withdrawn routes
    uint16_t withdrawn_route_length;
    struct list_head withdrawn_routes;
    //Path attribute
    uint16_t path_attr_length;
    //Path attributes indexed by their value (0 - 255)
    struct bgp_path_attribute *path_attrs[MAX_ATTRIBUTE + 1];
    //NLRI Information
    struct list_head nlri;
};


/*
 * BGP NOTIFICATION Error Codes and Subcodes (RFC 4271, RFC 4486)
 */

// Error Code 1: Message Header Error
#define BGP_ERR_HEADER              1
#define BGP_ERR_HEADER_SYNC         1  // Connection Not Synchronized (bad marker)
#define BGP_ERR_HEADER_LENGTH       2  // Bad Message Length
#define BGP_ERR_HEADER_TYPE         3  // Bad Message Type

// Error Code 2: OPEN Message Error
#define BGP_ERR_OPEN                2
#define BGP_ERR_OPEN_VERSION        1  // Unsupported Version Number
#define BGP_ERR_OPEN_PEER_AS        2  // Bad Peer AS
#define BGP_ERR_OPEN_BGP_ID         3  // Bad BGP Identifier
#define BGP_ERR_OPEN_OPT_PARAM      4  // Unsupported Optional Parameter
#define BGP_ERR_OPEN_HOLD_TIME      6  // Unacceptable Hold Time

// Error Code 3: UPDATE Message Error
#define BGP_ERR_UPDATE              3

// Error Code 4: Hold Timer Expired
#define BGP_ERR_HOLD_TIMER          4

// Error Code 5: Finite State Machine Error
#define BGP_ERR_FSM                 5

// Error Code 6: Cease (RFC 4486)
#define BGP_ERR_CEASE               6
#define BGP_ERR_CEASE_MAX_PREFIX    1  // Maximum Number of Prefixes Reached
#define BGP_ERR_CEASE_ADMIN_SHUT    2  // Administrative Shutdown
#define BGP_ERR_CEASE_PEER_DECONF   3  // Peer De-configured
#define BGP_ERR_CEASE_ADMIN_RESET   4  // Administrative Reset
#define BGP_ERR_CEASE_CONN_REJECT   5  // Connection Rejected
#define BGP_ERR_CEASE_CONFIG_CHG    6  // Other Configuration Change
#define BGP_ERR_CEASE_COLLISION     7  // Connection Collision Resolution
#define BGP_ERR_CEASE_RESOURCES     8  // Out of Resources

struct bgp_notification {
    uint8_t code;
    uint8_t subcode;
    unsigned char *data;
};

struct list_head;

struct bgp_msg {
    time_t recv_time;
    uint64_t id;
    //Peer name points to the string in struct bgp_peer;
    char *peer_name; 

    uint16_t length;
    uint16_t body_length;
    uint8_t type;

    union {
        struct bgp_open open;
        struct bgp_update *update;
        struct bgp_notification notification;
    };

    int actioned;
    struct list_head ingress;
    struct list_head output;
};



struct bgp_msg *recv_msg(int socket_fd);
int free_msg(struct bgp_msg *);
ssize_t send_open(int, uint8_t, uint16_t, uint16_t, uint32_t);
ssize_t send_keepalive(int);
ssize_t send_notification(int fd, uint8_t code, uint8_t subcode);

