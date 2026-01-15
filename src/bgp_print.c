#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include <jansson.h>


#include "bgp_peer.h"
#include "bgp_message.h"
#include "bgp_print.h"
#include "list.h"


int print_msg_stdout(struct bgp_peer *, struct bgp_msg *);
int print_msg_json(struct bgp_peer *, struct bgp_msg *);

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

void print_open(struct bgp_msg *);
void print_update(struct bgp_msg *);
void print_notification(struct bgp_msg *);
void print_keepalive(struct bgp_msg *);
void print_routerefresh(struct bgp_msg *);

int _set_bgp_output(struct bgp_peer *peer, enum bgp_output format) {
    switch (format) {
        case BGP_OUT_KV:
            peer->print_msg = print_msg_stdout;
            break;
        case BGP_OUT_JSON:
            peer->print_msg = print_msg_json;
            break;
        default:
            return -2;
    }

    return 0;
}

/*
 * Standard KV outputs
 */

int print_msg_stdout(struct bgp_peer *peer, struct bgp_msg *msg) {
    void (*dispatch[5]) (struct bgp_msg *) = {
        &print_open,
        &print_update,
        &print_notification,
        &print_keepalive,
        &print_routerefresh,
    };

    //Valid BGP message types are 1-5 (OPEN through ROUTE_REFRESH)
    if (msg->type < 1 || msg->type > 5) {
        return -1;
    }

    printf("recv_time=%ld name=%s id=%ld type=%s length=%d ", msg->recv_time, msg->peer_name, msg->id, type_string[ msg->type ],  msg->length);
    dispatch[msg->type - 1](msg);

    return 0;
}


void initialise_output(struct bgp_peer *peer) {
    //No lock needed - called during peer init before thread starts
    peer->print_msg = print_msg_stdout;
}

void print_open(struct bgp_msg *msg) {
    printf(
        "version=%d, asn=%d, hold_time=%d, router_id=%d, param_len=%d\n",
        msg->open.version,
        msg->open.asn,
        msg->open.hold_time,
        msg->open.router_id,
        msg->open.opt_param_len
    );

    //TODO: parameters
}

void print_pa_origin(struct bgp_path_attribute *pa) {
    char *origin_string[] = {
        "IGP",
        "EGP",
        "INCOMPLETE"
    };

    if (pa->origin > 2) {
        return;
    }

    printf("origin=%s ", origin_string[ pa->origin ]);
}

void print_pa_as_path(struct bgp_path_attribute *pa) {
    struct path_segment *seg;
    struct list_head *i;

    if (!pa->as_path) {
        return;
    }

    printf(
        "n_as_segments=%d n_total_as=%d ", pa->as_path->n_segments, pa->as_path->n_total_as
    );

    printf("as_path=\"");
    list_for_each(i, &pa->as_path->segments) {
        seg = list_entry(i, struct path_segment, list);
        for (int x = 0; x < seg->n_as; x++) {
            printf("%d", seg->as[x]);
            //No comma on the last entry
            if (x == seg->n_as - 1) {
                break;
            }
            printf(",");
        }
    }
    printf("\" ");
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



//This is gross and yuck
void print_ipv4(uint32_t ipv4) {
    char *ipv4_str = ipv4_string(ipv4);

    if (!ipv4_str) {
        return;
    }

    printf("%s", ipv4_str);
}

void print_next_hop(struct bgp_path_attribute *pa) {
    printf("next_hop=");
    print_ipv4(pa->next_hop);
    printf(" ");
}

void print_med(struct bgp_path_attribute *pa) {
    printf("med=%d ", pa->multi_exit_disc);
}

void print_local_pref(struct bgp_path_attribute *pa) {
    printf("local_pref=%d ", pa->local_pref);
}

void print_atomic_aggregate(struct bgp_path_attribute *pa) {
    printf("atomic_aggregate=1 ");
}

void print_aggregator(struct bgp_path_attribute *pa) {
    if (!pa->aggregator) {
        return;
    }
    printf("aggregator_asn=%d ", pa->aggregator->asn);
    printf("aggregator_ip=");
    print_ipv4(pa->aggregator->ip);
    printf(" ");
}


void print_update(struct bgp_msg *msg) {
    struct list_head *i;
    struct ipv4_nlri *nlri;

    //+1 to account for 0 at the start
    void (*path_attr_dispatch[AGGREGATOR + 1]) (struct bgp_path_attribute *) = {
        NULL,
        &print_pa_origin,
        &print_pa_as_path,
        &print_next_hop,
        &print_med,
        &print_local_pref,
        &print_atomic_aggregate,
        &print_aggregator
    };


    //Print withdrawn routes
    printf(
        "widthdrawn_route_length=%d withdrawn_routes=\"",
        msg->update->withdrawn_route_length
    );

    list_for_each(i, &msg->update->withdrawn_routes) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        printf("%s", nlri->string);
        if (!list_is_last(i, &msg->update->withdrawn_routes)) {
            printf(",");
        }
    }
    printf("\" ");


    //Print path attributes
    printf(
        "path_attribute_length=%d ",
        msg->update->path_attr_length
    );
    for (int x = 0; x < AGGREGATOR; x++) {
        if (!msg->update->path_attrs[x] || !path_attr_dispatch[x]) {
            continue;
        }

        path_attr_dispatch[x](msg->update->path_attrs[x]);
    }

    //Print NLRI
    printf("nlri=\"");
    list_for_each(i, &msg->update->nlri) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        printf("%s", nlri->string);
        if (!list_is_last(i, &msg->update->nlri)) {
            printf(",");
        }
    }
    printf("\"\n");
}


void print_notification(struct bgp_msg *msg) {
    printf(
        "code=%d, subcode=%d, data=\n",
        msg->notification.code,
        msg->notification.subcode
    );

}

void print_keepalive(struct bgp_msg *msg) {
    printf("\n");
}

void print_routerefresh(struct bgp_msg *msg) {

}


/*
 * JSON Output
 */
json_t *construct_json_open(struct bgp_msg *);
json_t *construct_json_update(struct bgp_msg *);
json_t *construct_json_notification(struct bgp_msg *);
json_t *construct_json_keepalive(struct bgp_msg *);
json_t *construct_json_routerefresh(struct bgp_msg *);


int print_msg_json(struct bgp_peer *peer, struct bgp_msg *msg) {
    json_t * (*dispatch[5]) (struct bgp_msg *) = {
        &construct_json_open,
        &construct_json_update,
        &construct_json_notification,
        &construct_json_keepalive,
        &construct_json_routerefresh,
    };

    //Valid BGP message types are 1-5 (OPEN through ROUTE_REFRESH)
    if (msg->type < 1 || msg->type > 5) {
        return -1;
    }

    json_t *root = json_object();

    json_object_set_new( root, "recv_time", json_integer(msg->recv_time) );
    json_object_set_new( root, "peer_name", json_string(msg->peer_name) );
    json_object_set_new( root, "id", json_integer(msg->id) );
    json_object_set_new( root, "type", json_string(type_string[ msg->type ]) );
    json_object_set_new( root, "length", json_integer(msg->length) );

    json_object_set_new( root, "message", dispatch[msg->type - 1](msg) );

    char *json_string = json_dumps(root, JSON_INDENT(2));
    printf("%s\n", json_string);

    free(json_string);
    json_decref(root);

    return 0;
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

    return leaf;
}


json_t *construct_json_pa_origin(struct bgp_path_attribute *);
json_t *construct_json_pa_as_path(struct bgp_path_attribute *);
json_t *construct_json_next_hop(struct bgp_path_attribute *);
json_t *construct_json_med(struct bgp_path_attribute *);
json_t *construct_json_local_pref(struct bgp_path_attribute *);
json_t *construct_json_atomic_aggregate(struct bgp_path_attribute *);
json_t *construct_json_aggregator(struct bgp_path_attribute *);

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
        "AGGREGATOR"
    };


    //+1 to account for 0 at the start
    json_t *(*path_attr_dispatch[AGGREGATOR + 1]) (struct bgp_path_attribute *) = {
        NULL,
        &construct_json_pa_origin,
        &construct_json_pa_as_path,
        &construct_json_next_hop,
        &construct_json_med,
        &construct_json_local_pref,
        &construct_json_atomic_aggregate,
        &construct_json_aggregator
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
    for (int x = 0; x <= AGGREGATOR; x++) {
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
