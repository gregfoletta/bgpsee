#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>


#include "bgp_peer.h"
#include "bgp_message.h"
#include "bgp_print.h"
#include "bgp_strings.h"
#include "bgp_path_attributes.h"
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
    //We've removed non-JSON output in version 0.0.4
    return 0;
}

void initialise_output(struct bgp_peer *peer) {
    pthread_mutex_lock(&peer->stdout_lock);

    peer->print_msg = print_msg_stdout;
}

/*
 * The assumption here is that we're using this after we've pulled
 * the IPv4 address off the network, thus it's in host byte order,
 */

//TODO: defined as static because it's also in bgp_path_attributes.
//Should be pulled out with other helpers into another file at some point
static char *ipv4_string(uint32_t ipv4) {
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


int print_msg_json(struct bgp_peer *peer, struct bgp_msg *msg) {
    json_t * (*dispatch[5]) (struct bgp_msg *) = {
        &construct_json_open,
        &construct_json_update,
        &construct_json_notification,
        &construct_json_keepalive,
        &construct_json_routerefresh,
    };

    json_t *root = json_object();

    json_object_set_new( root, "recv_time", json_integer(msg->recv_time) );
    json_object_set_new( root, "peer_name", json_string(msg->peer_name) );
    json_object_set_new( root, "id", json_integer(msg->id) );
    json_object_set_new( root, "type", json_string(type_string[ msg->type ]) );
    json_object_set_new( root, "length", json_integer(msg->length) );


    if (msg->type > 4) {
        return -1;
    }

    json_object_set_new( root, "message", dispatch[msg->type - 1](msg) );

    char *json_string = json_dumps(root, JSON_INDENT(2));
    printf("%s\n", json_string);

    free(json_string);
    json_decref(root);

    return 0;
}

json_t *construct_cap_unknown_or_empty(struct bgp_capability *cap) {
    json_t *leaf = json_object();

    return leaf;
} 

json_t *construct_cap_mp_ext(struct bgp_capability *cap) {
    json_t *mp_ext_j = json_object();

    json_object_set_new( mp_ext_j, "afi", json_string( afi_string(cap->mp_ext->afi) ) );
    json_object_set_new( mp_ext_j, "safi", json_string( safi_string(cap->mp_ext->safi) ) );

    return mp_ext_j;
}

json_t *construct_capability(struct bgp_capability *cap) {
    json_t *leaf = json_object();

    json_t * (*capability_dispatch[256]) (struct bgp_capability *);
    for (int x = 0; x < 254; x++) {
        capability_dispatch[x] = &construct_cap_unknown_or_empty;
    }

    capability_dispatch[1] = &construct_cap_mp_ext;


    json_object_set_new( leaf, "code", json_string( capability_string(cap->code) ) );
    json_object_set_new( leaf, "length", json_integer(cap->length) );
    json_object_set_new( leaf, "value", capability_dispatch[ cap->code ](cap) );

    return leaf;
}

json_t *construct_json_open(struct bgp_msg *msg) {
    json_t *leaf = json_object();
    struct list_head *i;
    struct bgp_parameter *param;
    char *router_id;

    json_object_set_new( leaf, "version", json_integer(msg->open.version) );
    json_object_set_new( leaf, "asn", json_integer(msg->open.asn) );
    json_object_set_new( leaf, "hold_time", json_integer(msg->open.hold_time) );

    router_id = ipv4_string(msg->open.router_id);
    json_object_set_new( leaf, "router_id", json_string(router_id) );
    free(router_id);

    json_object_set_new( leaf, "optional_parameter_length", json_integer(msg->open.opt_param_len) );


    json_t *parameters_j = json_array();
    list_for_each(i, &msg->open.parameters) {
        json_t *parameter_j = json_object();

        param = list_entry(i, struct bgp_parameter, list);
        json_object_set_new( parameter_j, "type", json_string( parameter_string(param->type) ) );
        json_object_set_new( parameter_j, "length", json_integer(param->length) );

        json_object_set_new( parameter_j, "value", construct_capability( param->capability ) );

        json_array_append_new( parameters_j, parameter_j);
    }

    json_object_set_new( leaf, "parameters", parameters_j );

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
    struct path_attr_funcs pa_dispatch;

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

    json_t *path_attributes = json_array();

    //Loop around all 256 path attributes
    for (int x = 0; x < 256; x++) {
        //No attribute in the array
        if (!msg->update->path_attrs[x]) {
            continue;
        }

        //Get the dispatch table
        pa_dispatch = get_path_attr_dispatch((uint8_t) x);

        json_t *path_attribute = json_object();
        json_t *path_attribute_specific;
        json_t *flags = json_array();


        json_object_set_new( path_attribute, "type", json_string(path_attribute_string((uint8_t) x)) );
        json_object_set_new( path_attribute, "type_code", json_integer(x) );

        //Path attribute flags
        json_array_append_new( flags, json_string(pa_flag_optional_string( msg->update->path_attrs[x]->flags )));
        json_array_append_new( flags, json_string(pa_flag_transitive_string( msg->update->path_attrs[x]->flags )));
        json_array_append_new( flags, json_string(pa_flag_partial_string( msg->update->path_attrs[x]->flags )));
        json_array_append_new( flags, json_string(pa_flag_extended_string( msg->update->path_attrs[x]->flags )) );
        json_object_set_new(path_attribute, "flags", flags);


        json_object_set_new(path_attribute, "flags_low_nibble", json_integer(msg->update->path_attrs[x]->flags & 0xF));

        //Add details about the known path attribute
        path_attribute_specific = pa_dispatch.json(msg->update->path_attrs[x]);
        json_object_update( path_attribute, path_attribute_specific );
        json_decref(path_attribute_specific);
        
        json_array_append_new(path_attributes, path_attribute);
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
