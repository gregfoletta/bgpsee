#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "list.h"

/* Forward declaration for capabilities */
struct bgp_capabilities;

// Max IPv4 CIDR string: "255.255.255.255/32" (18 chars) + null
#define MAX_IPV4_ROUTE_STRING 20
// Max IPv6 CIDR string: "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/128" (43 chars) + null
#define MAX_IPV6_ROUTE_STRING 48

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
    struct bgp_capabilities *capabilities;  // Parsed capabilities from optional params
};

/*
 UPDATE message and its dependencies
 https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
*/

struct path_segment {
    uint8_t type;
    uint8_t n_as;
    uint32_t *as;  // 4-byte ASNs (RFC 6793)
    struct list_head list;
};

struct as_path {
    int n_segments;
    int n_total_as;
    struct list_head segments;
};

struct aggregator {
    uint32_t asn;  // 4-byte ASN (RFC 6793)
    uint32_t ip;
};

struct community {
    uint16_t n_communities;
    uint32_t *communities;
};

struct large_community_value {
    uint32_t global_admin;
    uint32_t local_data_1;
    uint32_t local_data_2;
};

struct large_community {
    uint16_t n_communities;
    struct large_community_value *communities;
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
        struct community *community;
        struct large_community *large_community;
        struct mp_reach_nlri *mp_reach;
        struct mp_unreach_nlri *mp_unreach;
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

struct ipv6_nlri {
    uint8_t length;      /* Prefix length in bits */
    uint8_t bytes;       /* Number of bytes needed for prefix */
    uint8_t prefix[16];  /* IPv6 prefix (up to 128 bits) */
    struct list_head list;
    char string[MAX_IPV6_ROUTE_STRING];
};

/*
 * EVPN Route Types (RFC 7432, RFC 9136)
 */
enum evpn_route_type {
    EVPN_ETH_AUTO_DISCOVERY = 1,
    EVPN_MAC_IP_ADV         = 2,
    EVPN_INCLUSIVE_MCAST    = 3,
    EVPN_ETH_SEGMENT       = 4,
    EVPN_IP_PREFIX          = 5,
};

/*
 * EVPN NLRI entry - stores parsed binary data from EVPN route
 */
struct evpn_nlri {
    uint8_t route_type;
    uint8_t route_length;         /* bytes of route-type-specific data */

    /* Route Distinguisher (all types) */
    uint16_t rd_type;
    uint8_t rd_value[6];

    /* Ethernet Segment Identifier (Type 1, 2, 4, 5) */
    uint8_t esi[10];

    /* Ethernet Tag (Type 1, 2, 3, 5) */
    uint32_t ethernet_tag;

    /* MAC Address (Type 2) */
    uint8_t mac_length;           /* bits (48) */
    uint8_t mac[6];

    /* IP Address (Type 2, 3, 4, 5) */
    uint8_t ip_length;            /* bits (0, 32, or 128) */
    uint8_t ip[16];

    /* Gateway IP (Type 5) */
    uint8_t gw_ip[16];

    /* IP prefix length (Type 5 only) */
    uint8_t prefix_length;

    /* MPLS Labels */
    uint32_t mpls_label1;
    uint32_t mpls_label2;         /* Type 2 optional L3 VNI */

    struct list_head list;
};

/*
 * MP_REACH_NLRI (Type 14) - RFC 4760
 * Carries reachable routes for non-IPv4 unicast address families
 */
struct mp_reach_nlri {
    uint16_t afi;           /* Address Family Identifier */
    uint8_t safi;           /* Subsequent Address Family Identifier */
    uint8_t nh_length;      /* Next Hop length in bytes */
    uint8_t next_hop[32];   /* Next Hop address (up to 32 bytes for IPv6 link-local) */
    char nh_string[40];     /* Formatted next hop (global) */
    char nh_link_local_string[40];  /* Formatted link-local next hop (if present) */
    struct list_head nlri;  /* List of ipv6_nlri (or ipv4_nlri depending on AFI) */
};

/*
 * MP_UNREACH_NLRI (Type 15) - RFC 4760
 * Carries withdrawn routes for non-IPv4 unicast address families
 */
struct mp_unreach_nlri {
    uint16_t afi;                   /* Address Family Identifier */
    uint8_t safi;                   /* Subsequent Address Family Identifier */
    struct list_head withdrawn;     /* List of withdrawn routes */
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
    AGGREGATOR,
    COMMUNITY,
    /* ... gap ... */
    MP_REACH_NLRI = 14,
    MP_UNREACH_NLRI = 15,
    /* ... gap ... */
    LARGE_COMMUNITY = 32
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



/*
 * Receive and parse a BGP message from the socket.
 * Uses peer->socket.fd for the socket and peer->four_octet_asn for AS_PATH parsing.
 */
struct bgp_peer;
struct bgp_msg *recv_msg(struct bgp_peer *peer);
struct bgp_msg *alloc_sent_msg(void);
int free_msg(struct bgp_msg *);
ssize_t send_open(int fd, uint8_t version, uint16_t asn, uint16_t hold_time,
                  uint32_t router_id, const struct bgp_capabilities *caps);
ssize_t send_keepalive(int);
ssize_t send_notification(int fd, uint8_t code, uint8_t subcode);

