#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include <jansson.h>


#include "bgp_peer.h"
#include "bgp_message.h"
#include "bgp_capability.h"
#include "bgp_print.h"
#include "byte_conv.h"
#include "list.h"


int print_msg_json(struct bgp_peer *, struct bgp_msg *);
int print_msg_jsonl(struct bgp_peer *, struct bgp_msg *);

    char *type_string[] = {
        "<NULL>",
        "OPEN",
        "UPDATE",
        "NOTIFICATON",
        "KEEPALIVE",
        "ROUTE-REFRESH"
    };

/* NOTE:
 * The code in here is far from perfect, but gets the job done.
 * Please leave your judgement at the door
 */

int _set_bgp_output(struct bgp_peer *peer, enum bgp_output format) {
    switch (format) {
        case BGP_OUT_JSON:
            peer->print_msg = print_msg_json;
            peer->output_format = BGP_OUT_JSON;
            break;
        case BGP_OUT_JSONL:
            peer->print_msg = print_msg_jsonl;
            peer->output_format = BGP_OUT_JSONL;
            break;
        default:
            return -2;
    }

    return 0;
}

void initialise_output(struct bgp_peer *peer) {
    //No lock needed - called during peer init before thread starts
    peer->print_msg = print_msg_json;
    peer->output_format = BGP_OUT_JSON;
}


/*
 * The assumption here is that we're using this after we've pulled
 * the IPv4 address off the network, thus it's in host byte order,
 */
char *ipv4_string(uint32_t ipv4) {
    uint8_t octets[4];
    char *ipv4_string;

    //IPv4 max string size is (4 * 3){octets} + (3 * 1){dots} + (1){NULL} = 16
    #define MAX_IPV4_STRING 16
    ipv4_string = calloc(MAX_IPV4_STRING, sizeof(*ipv4_string));

    if (!ipv4_string) {
        return NULL;
    }

    octets[0] = (uint8_t) ((ipv4 & 0xff000000) >> 24);
    octets[1] = (uint8_t) ((ipv4 & 0x00ff0000) >> 16);
    octets[2] = (uint8_t) ((ipv4 & 0x0000ff00) >> 8);
    octets[3] = (uint8_t) (ipv4 & 0x000000ff);

    snprintf(
        ipv4_string,
        MAX_IPV4_STRING,
        "%d.%d.%d.%d",
        octets[3],
        octets[2],
        octets[1],
        octets[0]
    );

    return ipv4_string;
}





/*
 * JSON Output
 */
json_t *construct_json_open(struct bgp_msg *);
json_t *construct_json_update(struct bgp_msg *);
json_t *construct_json_notification(struct bgp_msg *);
json_t *construct_json_keepalive(struct bgp_msg *);
json_t *construct_json_routerefresh(struct bgp_msg *);


/*
 * format_msg_json_internal() - Format a BGP message as JSON string
 *
 * Returns a malloc'd string that the caller must free, or NULL on error.
 */
static char *format_msg_json_internal(struct bgp_msg *msg, size_t flags) {
    json_t * (*dispatch[5]) (struct bgp_msg *) = {
        &construct_json_open,
        &construct_json_update,
        &construct_json_notification,
        &construct_json_keepalive,
        &construct_json_routerefresh,
    };

    //Valid BGP message types are 1-5 (OPEN through ROUTE_REFRESH)
    if (msg->type < 1 || msg->type > 5) {
        return NULL;
    }

    json_t *root = json_object();

    json_object_set_new( root, "time", json_integer(msg->recv_time) );
    json_object_set_new( root, "peer_name", json_string(msg->peer_name) );
    json_object_set_new( root, "id", json_integer(msg->id) );
    json_object_set_new( root, "type", json_string(type_string[ msg->type ]) );
    json_object_set_new( root, "length", json_integer(msg->length) );

    json_object_set_new( root, "message", dispatch[msg->type - 1](msg) );

    char *json_str = json_dumps(root, flags);
    json_decref(root);

    return json_str;
}

static int print_msg_json_internal(struct bgp_msg *msg, size_t flags) {
    char *json_str = format_msg_json_internal(msg, flags);
    if (!json_str) {
        return -1;
    }
    printf("%s\n", json_str);
    free(json_str);
    return 0;
}

int print_msg_json(struct bgp_peer *peer, struct bgp_msg *msg) {
    return print_msg_json_internal(msg, JSON_INDENT(2));
}

int print_msg_jsonl(struct bgp_peer *peer, struct bgp_msg *msg) {
    return print_msg_json_internal(msg, JSON_COMPACT);
}

/*
 * Format functions - return malloc'd string, caller must free
 */
char *format_msg_json(struct bgp_msg *msg) {
    return format_msg_json_internal(msg, JSON_INDENT(2));
}

char *format_msg_jsonl(struct bgp_msg *msg) {
    return format_msg_json_internal(msg, JSON_COMPACT);
}



/* Helper to get AFI name string */
static const char *afi_name(uint16_t afi) {
    switch (afi) {
        case BGP_AFI_IPV4:  return "IPv4";
        case BGP_AFI_IPV6:  return "IPv6";
        case BGP_AFI_L2VPN: return "L2VPN";
        default:            return "Unknown";
    }
}

/* Helper to get SAFI name string */
static const char *safi_name(uint8_t safi) {
    switch (safi) {
        case BGP_SAFI_UNICAST:   return "Unicast";
        case BGP_SAFI_MULTICAST: return "Multicast";
        case BGP_SAFI_MPLS:      return "MPLS";
        case BGP_SAFI_EVPN:      return "EVPN";
        default:                 return "Unknown";
    }
}

/* Construct JSON object for a single capability */
static json_t *construct_json_capability(struct bgp_capability *cap) {
    json_t *cap_obj = json_object();

    json_object_set_new(cap_obj, "code", json_integer(cap->code));
    json_object_set_new(cap_obj, "name", json_string(bgp_capability_name(cap->code)));
    json_object_set_new(cap_obj, "length", json_integer(cap->length));

    /* Decode capability-specific values */
    switch (cap->code) {
        case BGP_CAP_MP_EXT:
            if (cap->length >= 4 && cap->value) {
                uint16_t afi = uchar_be_to_uint16(cap->value);
                uint8_t safi = cap->value[3];
                json_object_set_new(cap_obj, "afi", json_integer(afi));
                json_object_set_new(cap_obj, "afi_name", json_string(afi_name(afi)));
                json_object_set_new(cap_obj, "safi", json_integer(safi));
                json_object_set_new(cap_obj, "safi_name", json_string(safi_name(safi)));
            }
            break;

        case BGP_CAP_FOUR_OCTET_ASN:
            if (cap->length >= 4 && cap->value) {
                uint32_t asn = ((uint32_t)cap->value[0] << 24) |
                               ((uint32_t)cap->value[1] << 16) |
                               ((uint32_t)cap->value[2] << 8) |
                               (uint32_t)cap->value[3];
                json_object_set_new(cap_obj, "asn", json_integer(asn));
            }
            break;

        case BGP_CAP_GRACEFUL_RESTART:
            if (cap->length >= 2 && cap->value) {
                uint16_t flags_time = uchar_be_to_uint16(cap->value);
                json_object_set_new(cap_obj, "restart_flags", json_integer((flags_time >> 12) & 0xF));
                json_object_set_new(cap_obj, "restart_time", json_integer(flags_time & 0x0FFF));
            }
            break;

        case BGP_CAP_ADD_PATH:
            if (cap->length >= 4 && cap->value) {
                json_t *add_paths = json_array();
                for (int i = 0; i + 3 < cap->length; i += 4) {
                    json_t *entry = json_object();
                    uint16_t afi = uchar_be_to_uint16(cap->value + i);
                    uint8_t safi = cap->value[i + 2];
                    uint8_t send_recv = cap->value[i + 3];
                    json_object_set_new(entry, "afi", json_integer(afi));
                    json_object_set_new(entry, "afi_name", json_string(afi_name(afi)));
                    json_object_set_new(entry, "safi", json_integer(safi));
                    json_object_set_new(entry, "safi_name", json_string(safi_name(safi)));
                    json_object_set_new(entry, "send_receive", json_integer(send_recv));
                    json_array_append_new(add_paths, entry);
                }
                json_object_set_new(cap_obj, "address_families", add_paths);
            }
            break;

        default:
            /* For unknown capabilities, include raw hex value if present */
            if (cap->length > 0 && cap->value) {
                char *hex = malloc((size_t)(cap->length * 2 + 1));
                if (hex) {
                    for (int i = 0; i < cap->length; i++) {
                        snprintf(hex + i * 2, 3, "%02x", cap->value[i]);
                    }
                    json_object_set_new(cap_obj, "value_hex", json_string(hex));
                    free(hex);
                }
            }
            break;
    }

    return cap_obj;
}

json_t *construct_json_open(struct bgp_msg *msg) {
    json_t *leaf = json_object();
    char *router_id;

    json_object_set_new( leaf, "version", json_integer(msg->open.version) );
    json_object_set_new( leaf, "asn", json_integer(msg->open.asn) );
    json_object_set_new( leaf, "hold_time", json_integer(msg->open.hold_time) );

    router_id = ipv4_string(msg->open.router_id);
    json_object_set_new( leaf, "router_id", json_string(router_id) );
    free(router_id);

    json_object_set_new( leaf, "optional_parameter_length", json_integer(msg->open.opt_param_len) );

    /* Add capabilities */
    if (msg->open.capabilities && msg->open.capabilities->count > 0) {
        json_t *caps_array = json_array();
        struct list_head *pos;
        struct bgp_capability *cap;

        list_for_each(pos, &msg->open.capabilities->caps) {
            cap = list_entry(pos, struct bgp_capability, list);
            json_array_append_new(caps_array, construct_json_capability(cap));
        }

        json_object_set_new(leaf, "capabilities", caps_array);
    }

    return leaf;
}


json_t *construct_json_pa_origin(struct bgp_path_attribute *);
json_t *construct_json_pa_as_path(struct bgp_path_attribute *);
json_t *construct_json_next_hop(struct bgp_path_attribute *);
json_t *construct_json_med(struct bgp_path_attribute *);
json_t *construct_json_local_pref(struct bgp_path_attribute *);
json_t *construct_json_atomic_aggregate(struct bgp_path_attribute *);
json_t *construct_json_aggregator(struct bgp_path_attribute *);
json_t *construct_json_community(struct bgp_path_attribute *);
json_t *construct_json_mp_reach(struct bgp_path_attribute *);
json_t *construct_json_mp_unreach(struct bgp_path_attribute *);
json_t *construct_json_large_community(struct bgp_path_attribute *);

json_t *construct_json_update(struct bgp_msg *msg) {
    struct list_head *i;
    struct ipv4_nlri *nlri;

    char *pa_id_to_name[] = {
        "<Invalid>",
        "ORIGIN",
        "AS_PATH",
        "NEXT_HOP",
        "MULTI_EXIT_DISC",
        "LOCAL_PREF",
        "ATOMIC_AGGREGATE",
        "AGGREGATOR",
        "COMMUNITY"
    };


    //+1 to account for 0 at the start
    json_t *(*path_attr_dispatch[COMMUNITY + 1]) (struct bgp_path_attribute *) = {
        NULL,
        &construct_json_pa_origin,
        &construct_json_pa_as_path,
        &construct_json_next_hop,
        &construct_json_med,
        &construct_json_local_pref,
        &construct_json_atomic_aggregate,
        &construct_json_aggregator,
        &construct_json_community
    };

    json_t *leaf = json_object();

    //Withdrawn Routes
    json_object_set_new( leaf, "withdrawn_route_length", json_integer(msg->update->withdrawn_route_length) );

    json_t* withdrawn_routes = json_array();
    list_for_each(i, &msg->update->withdrawn_routes) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        json_array_append_new( withdrawn_routes, json_string(nlri->string) );
    }
    json_object_set_new( leaf, "withdrawn_routes", withdrawn_routes);

    //Path attributes
    json_object_set_new( leaf, "path_attribute_length", json_integer(msg->update->path_attr_length) );
    json_t *path_attributes = json_object();
    for (int x = 0; x <= COMMUNITY; x++) {
        if (!msg->update->path_attrs[x] || !path_attr_dispatch[x]) {
            continue;
        }
        //Add the new path attribute object
        json_object_set_new(
            path_attributes,
            pa_id_to_name[x],
            path_attr_dispatch[x](msg->update->path_attrs[x])
        );
    }

    /* Handle MP_REACH_NLRI (type 14) */
    if (msg->update->path_attrs[MP_REACH_NLRI]) {
        json_object_set_new(
            path_attributes,
            "MP_REACH_NLRI",
            construct_json_mp_reach(msg->update->path_attrs[MP_REACH_NLRI])
        );
    }

    /* Handle MP_UNREACH_NLRI (type 15) */
    if (msg->update->path_attrs[MP_UNREACH_NLRI]) {
        json_object_set_new(
            path_attributes,
            "MP_UNREACH_NLRI",
            construct_json_mp_unreach(msg->update->path_attrs[MP_UNREACH_NLRI])
        );
    }

    /* Handle LARGE_COMMUNITY (type 32) */
    if (msg->update->path_attrs[LARGE_COMMUNITY]) {
        json_object_set_new(
            path_attributes,
            "LARGE_COMMUNITY",
            construct_json_large_community(msg->update->path_attrs[LARGE_COMMUNITY])
        );
    }

    json_object_set_new( leaf, "path_attributes", path_attributes );
    
    //NLRI
    json_t *routes = json_array();
    list_for_each(i, &msg->update->nlri) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        json_array_append_new( routes, json_string(nlri->string) );
    }
    json_object_set_new( leaf, "nlri", routes );
    
    return leaf;

}

json_t *construct_json_pa_origin(struct bgp_path_attribute *attr) {
    char *origin_string[] = {
        "IGP",
        "EGP",
        "INCOMPLETE"
    };

    if (attr->origin > 2) {
        return json_object();
    }

    return json_string(origin_string[ attr->origin ]);
}

json_t *construct_json_pa_as_path(struct bgp_path_attribute *attr) {
    struct path_segment *seg;
    struct list_head *i;
    json_t *as_path = json_object();

    char *as_type_id_to_name[] = {
        "<Invalid>",
        "AS_SET",
        "AS_SEQUENCE"
    };

    if (!attr->as_path) {
        return json_object();
    }

    json_object_set_new( as_path, "n_as_segments", json_integer(attr->as_path->n_segments) );
    json_object_set_new( as_path, "n_total_as", json_integer(attr->as_path->n_total_as) );

    json_t *path_segments = json_array();
    list_for_each(i, &attr->as_path->segments) {
        json_t *path_segment = json_object();
        seg = list_entry(i, struct path_segment, list);

        //Invalid segment type
        if (seg->type == 0 || seg->type > 2) {
            json_object_set_new( path_segment, "type", json_string("Invalid") );
        }
        json_object_set_new( path_segment, "type", json_string(as_type_id_to_name[ seg->type]) );
        json_object_set_new( path_segment, "n_as", json_integer(seg->n_as) );

        json_t *asns = json_array();
        for (int x = 0; x < seg->n_as; x++) {
            json_array_append_new( asns, json_integer(seg->as[x]) );
        }
        json_object_set_new( path_segment, "asns", asns );
        json_array_append_new( path_segments, path_segment );
    }

    json_object_set_new( as_path, "path_segments", path_segments );

    return as_path;
}

json_t *construct_json_next_hop(struct bgp_path_attribute *attr) {
    char *nh_str = ipv4_string(attr->next_hop);
    json_t *nh = json_string(nh_str);
    free(nh_str);

    return nh;
}

json_t *construct_json_med(struct bgp_path_attribute *attr) {
    return json_integer(attr->multi_exit_disc);
}

json_t *construct_json_local_pref(struct bgp_path_attribute *attr) {
    return json_integer(attr->local_pref);
}

json_t *construct_json_atomic_aggregate(struct bgp_path_attribute *attr) {
    return json_boolean(1);
}

json_t *construct_json_aggregator(struct bgp_path_attribute *attr) {
    json_t *aggregator = json_object();

    if (!attr->aggregator) {
        return aggregator;
    }

    char *agg_ip_str = ipv4_string(attr->aggregator->ip);

    json_object_set_new( aggregator, "aggregator_asn", json_integer(attr->aggregator->asn) );
    json_object_set_new( aggregator, "aggregator_ip", json_string(agg_ip_str) );

    free(agg_ip_str);

    return aggregator;
}

json_t *construct_json_community(struct bgp_path_attribute *attr) {
    json_t *communities = json_array();

    if (!attr->community) {
        return communities;
    }

    for (uint16_t i = 0; i < attr->community->n_communities; i++) {
        uint32_t val = attr->community->communities[i];
        char buf[32];

        if (val == 0xFFFFFF01) {
            json_array_append_new(communities, json_string("NO_EXPORT"));
        } else if (val == 0xFFFFFF02) {
            json_array_append_new(communities, json_string("NO_ADVERTISE"));
        } else if (val == 0xFFFFFF03) {
            json_array_append_new(communities, json_string("NO_EXPORT_SUBCONFED"));
        } else {
            uint16_t high = (uint16_t)(val >> 16);
            uint16_t low = (uint16_t)(val & 0xFFFF);
            snprintf(buf, sizeof(buf), "%u:%u", high, low);
            json_array_append_new(communities, json_string(buf));
        }
    }

    return communities;
}

json_t *construct_json_large_community(struct bgp_path_attribute *attr) {
    json_t *communities = json_array();

    if (!attr->large_community) {
        return communities;
    }

    for (uint16_t i = 0; i < attr->large_community->n_communities; i++) {
        char buf[48];
        snprintf(buf, sizeof(buf), "%u:%u:%u",
                 attr->large_community->communities[i].global_admin,
                 attr->large_community->communities[i].local_data_1,
                 attr->large_community->communities[i].local_data_2);
        json_array_append_new(communities, json_string(buf));
    }

    return communities;
}

/* EVPN formatting helpers */

static void format_mac_address(char *buf, size_t len, const uint8_t *mac) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_esi(char *buf, size_t len, const uint8_t *esi) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             esi[0], esi[1], esi[2], esi[3], esi[4],
             esi[5], esi[6], esi[7], esi[8], esi[9]);
}

static void format_rd(char *buf, size_t len, uint16_t type, const uint8_t *value) {
    unsigned char *v = (unsigned char *)value;
    switch (type) {
    case 0: {
        /* Type 0: 2-byte admin : 4-byte number */
        uint16_t admin = uchar_be_to_uint16(v);
        uint32_t number = uchar_be_to_uint32(v + 2);
        snprintf(buf, len, "%u:%u", admin, number);
        break;
    }
    case 1: {
        /* Type 1: 4-byte IP : 2-byte number */
        uint16_t number = uchar_be_to_uint16(v + 4);
        snprintf(buf, len, "%u.%u.%u.%u:%u",
                 value[0], value[1], value[2], value[3], number);
        break;
    }
    case 2: {
        /* Type 2: 4-byte ASN : 2-byte number */
        uint32_t asn = uchar_be_to_uint32(v);
        uint16_t number = uchar_be_to_uint16(v + 4);
        snprintf(buf, len, "%u:%u", asn, number);
        break;
    }
    default:
        snprintf(buf, len, "%u:%02x%02x%02x%02x%02x%02x",
                 type, value[0], value[1], value[2], value[3], value[4], value[5]);
        break;
    }
}

static void format_evpn_ip(char *buf, size_t len, const uint8_t *ip, uint8_t ip_len_bits) {
    if (ip_len_bits == 32) {
        snprintf(buf, len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    } else if (ip_len_bits == 128) {
        /* Use RFC 5952 compressed format */
        unsigned char *addr = (unsigned char *)ip;
        uint16_t groups[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = uchar_be_to_uint16(addr + i * 2);
        }
        int best_start = -1, best_len = 1;
        int cur_start = -1, cur_len = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (cur_start == -1) cur_start = i;
                cur_len++;
            } else {
                if (cur_len > best_len) {
                    best_start = cur_start;
                    best_len = cur_len;
                }
                cur_start = -1;
                cur_len = 0;
            }
        }
        if (cur_len > best_len) {
            best_start = cur_start;
            best_len = cur_len;
        }
        char *p = buf;
        char *endp = buf + len;
        for (int i = 0; i < 8 && p < endp; i++) {
            if (best_start >= 0 && i == best_start) {
                p += snprintf(p, (size_t)(endp - p), "::");
                i += best_len - 1;
            } else {
                if (i > 0 && !(best_start >= 0 && i == best_start + best_len)) {
                    p += snprintf(p, (size_t)(endp - p), ":");
                }
                p += snprintf(p, (size_t)(endp - p), "%x", groups[i]);
            }
        }
    } else {
        buf[0] = '\0';
    }
}

static const char *evpn_route_type_name(uint8_t type) {
    switch (type) {
    case EVPN_ETH_AUTO_DISCOVERY: return "Ethernet Auto-Discovery";
    case EVPN_MAC_IP_ADV:         return "MAC/IP Advertisement";
    case EVPN_INCLUSIVE_MCAST:    return "Inclusive Multicast Ethernet Tag";
    case EVPN_ETH_SEGMENT:       return "Ethernet Segment";
    case EVPN_IP_PREFIX:          return "IP Prefix";
    default:                      return "Unknown";
    }
}

static json_t *construct_json_evpn_nlri(struct evpn_nlri *nlri) {
    json_t *obj = json_object();
    char buf[64];

    json_object_set_new(obj, "route_type", json_integer(nlri->route_type));
    json_object_set_new(obj, "route_type_name", json_string(evpn_route_type_name(nlri->route_type)));

    /* RD (all types) */
    format_rd(buf, sizeof(buf), nlri->rd_type, nlri->rd_value);
    json_object_set_new(obj, "rd", json_string(buf));

    switch (nlri->route_type) {
    case EVPN_ETH_AUTO_DISCOVERY:
        format_esi(buf, sizeof(buf), nlri->esi);
        json_object_set_new(obj, "esi", json_string(buf));
        json_object_set_new(obj, "ethernet_tag", json_integer(nlri->ethernet_tag));
        if (nlri->mpls_label1) {
            json_object_set_new(obj, "mpls_label", json_integer(nlri->mpls_label1));
        }
        break;

    case EVPN_MAC_IP_ADV:
        format_esi(buf, sizeof(buf), nlri->esi);
        json_object_set_new(obj, "esi", json_string(buf));
        json_object_set_new(obj, "ethernet_tag", json_integer(nlri->ethernet_tag));
        format_mac_address(buf, sizeof(buf), nlri->mac);
        json_object_set_new(obj, "mac", json_string(buf));
        if (nlri->ip_length > 0) {
            format_evpn_ip(buf, sizeof(buf), nlri->ip, nlri->ip_length);
            json_object_set_new(obj, "ip", json_string(buf));
        }
        if (nlri->mpls_label1) {
            json_object_set_new(obj, "mpls_label", json_integer(nlri->mpls_label1));
        }
        if (nlri->mpls_label2) {
            json_object_set_new(obj, "mpls_label2", json_integer(nlri->mpls_label2));
        }
        break;

    case EVPN_INCLUSIVE_MCAST:
        json_object_set_new(obj, "ethernet_tag", json_integer(nlri->ethernet_tag));
        if (nlri->ip_length > 0) {
            format_evpn_ip(buf, sizeof(buf), nlri->ip, nlri->ip_length);
            json_object_set_new(obj, "ip", json_string(buf));
        }
        break;

    case EVPN_ETH_SEGMENT:
        format_esi(buf, sizeof(buf), nlri->esi);
        json_object_set_new(obj, "esi", json_string(buf));
        if (nlri->ip_length > 0) {
            format_evpn_ip(buf, sizeof(buf), nlri->ip, nlri->ip_length);
            json_object_set_new(obj, "ip", json_string(buf));
        }
        break;

    case EVPN_IP_PREFIX:
        format_esi(buf, sizeof(buf), nlri->esi);
        json_object_set_new(obj, "esi", json_string(buf));
        json_object_set_new(obj, "ethernet_tag", json_integer(nlri->ethernet_tag));
        if (nlri->ip_length > 0) {
            format_evpn_ip(buf, sizeof(buf), nlri->ip, nlri->ip_length);
            char prefix_buf[68];
            snprintf(prefix_buf, sizeof(prefix_buf), "%s/%u", buf, nlri->prefix_length);
            json_object_set_new(obj, "ip_prefix", json_string(prefix_buf));
        }
        if (nlri->ip_length == 32) {
            format_evpn_ip(buf, sizeof(buf), nlri->gw_ip, 32);
        } else {
            format_evpn_ip(buf, sizeof(buf), nlri->gw_ip, 128);
        }
        json_object_set_new(obj, "gateway_ip", json_string(buf));
        if (nlri->mpls_label1) {
            json_object_set_new(obj, "mpls_label", json_integer(nlri->mpls_label1));
        }
        break;
    }

    return obj;
}

json_t *construct_json_mp_reach(struct bgp_path_attribute *attr) {
    json_t *mp = json_object();
    struct list_head *i;

    if (!attr->mp_reach) {
        return mp;
    }

    json_object_set_new(mp, "afi", json_integer(attr->mp_reach->afi));
    json_object_set_new(mp, "afi_name", json_string(afi_name(attr->mp_reach->afi)));
    json_object_set_new(mp, "safi", json_integer(attr->mp_reach->safi));
    json_object_set_new(mp, "safi_name", json_string(safi_name(attr->mp_reach->safi)));

    /* Add next hop - already formatted during parsing */
    if (attr->mp_reach->nh_string[0]) {
        if (attr->mp_reach->nh_link_local_string[0]) {
            /* Dual next hop (global + link-local) */
            json_object_set_new(mp, "next_hop_global", json_string(attr->mp_reach->nh_string));
            json_object_set_new(mp, "next_hop_link_local", json_string(attr->mp_reach->nh_link_local_string));
        } else {
            json_object_set_new(mp, "next_hop", json_string(attr->mp_reach->nh_string));
        }
    }

    /* NLRI routes */
    json_t *nlri_array = json_array();
    if (attr->mp_reach->afi == BGP_AFI_L2VPN) {
        list_for_each(i, &attr->mp_reach->nlri) {
            struct evpn_nlri *nlri = list_entry(i, struct evpn_nlri, list);
            json_array_append_new(nlri_array, construct_json_evpn_nlri(nlri));
        }
    } else if (attr->mp_reach->afi == BGP_AFI_IPV6) {
        list_for_each(i, &attr->mp_reach->nlri) {
            struct ipv6_nlri *nlri = list_entry(i, struct ipv6_nlri, list);
            json_array_append_new(nlri_array, json_string(nlri->string));
        }
    } else if (attr->mp_reach->afi == BGP_AFI_IPV4) {
        list_for_each(i, &attr->mp_reach->nlri) {
            struct ipv4_nlri *nlri = list_entry(i, struct ipv4_nlri, list);
            json_array_append_new(nlri_array, json_string(nlri->string));
        }
    }
    json_object_set_new(mp, "nlri", nlri_array);

    return mp;
}

json_t *construct_json_mp_unreach(struct bgp_path_attribute *attr) {
    json_t *mp = json_object();
    struct list_head *i;

    if (!attr->mp_unreach) {
        return mp;
    }

    json_object_set_new(mp, "afi", json_integer(attr->mp_unreach->afi));
    json_object_set_new(mp, "afi_name", json_string(afi_name(attr->mp_unreach->afi)));
    json_object_set_new(mp, "safi", json_integer(attr->mp_unreach->safi));
    json_object_set_new(mp, "safi_name", json_string(safi_name(attr->mp_unreach->safi)));

    /* Withdrawn routes */
    json_t *withdrawn_array = json_array();
    if (attr->mp_unreach->afi == BGP_AFI_L2VPN) {
        list_for_each(i, &attr->mp_unreach->withdrawn) {
            struct evpn_nlri *nlri = list_entry(i, struct evpn_nlri, list);
            json_array_append_new(withdrawn_array, construct_json_evpn_nlri(nlri));
        }
    } else if (attr->mp_unreach->afi == BGP_AFI_IPV6) {
        list_for_each(i, &attr->mp_unreach->withdrawn) {
            struct ipv6_nlri *nlri = list_entry(i, struct ipv6_nlri, list);
            json_array_append_new(withdrawn_array, json_string(nlri->string));
        }
    } else if (attr->mp_unreach->afi == BGP_AFI_IPV4) {
        list_for_each(i, &attr->mp_unreach->withdrawn) {
            struct ipv4_nlri *nlri = list_entry(i, struct ipv4_nlri, list);
            json_array_append_new(withdrawn_array, json_string(nlri->string));
        }
    }
    json_object_set_new(mp, "withdrawn_routes", withdrawn_array);

    return mp;
}


json_t *construct_json_notification(struct bgp_msg *msg) {
    json_t *leaf = json_object();

    json_object_set_new( leaf, "code", json_integer(msg->notification.code) );
    json_object_set_new( leaf, "subcode", json_integer(msg->notification.subcode) );

    return leaf;
}

json_t *construct_json_keepalive(struct bgp_msg *msg) {
    return json_object();
}
json_t *construct_json_routerefresh(struct bgp_msg *msg) {
    return json_object();
}
