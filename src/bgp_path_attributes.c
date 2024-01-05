#include <string.h>

#include "bgp_path_attributes.h"
#include "list.h"
#include "byte_conv.h"

struct path_segment {
    uint8_t type;
    uint8_t n_as;
    //Support four-octet ASNs
    uint32_t *as;
    struct list_head list;
};

struct as_path {
    int n_segments;
    int n_total_as;
    struct list_head segments;
};

struct aggregator {
    //Suport four-octet ASNs
    uint32_t asn;
    uint32_t ip;
};


struct path_attr_funcs *pa_dispatch;

//Convert the four byte ASNs into ASDot+ string
char *asdot_plus(uint32_t asn) {
    uint16_t high, low;
    char *asdot_plus;
    low = asn & 0xFFFF;
    high = (uint16_t) (asn & 0xFFFF0000) >> 16;

    //Maximum ASDot+ string is "65535.65535\0" == 12
    asdot_plus = calloc(12, sizeof(char));

    if (!asdot_plus) {
        return NULL;
    }

    snprintf(asdot_plus, 12, "%d.%d", high, low);

    return asdot_plus;
}


//Functions used when we aren't parsing the path attribute
//i.e. we haven't implemented the functionality yet
int pa_default(struct bgp_path_attribute *, unsigned char **, uint16_t);
json_t *pa_default_json(struct bgp_path_attribute *);
void pa_default_free(struct bgp_path_attribute *);



struct path_attr_funcs get_path_attr_dispatch(uint8_t type) {
    //We're assuming here that init_pa_dispatch() has been called
    return pa_dispatch[type];
}


int pa_default(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t length) {
    //Overflow checks need to happen in the calling function, not in this function
    //Not currently doing anything with this, but will keep it here for to perhaps
    //base64 it in the future
    //memcpy(pa->unparsed_value, *pos, length);

    *pos += length;

    return 0;
}

json_t *pa_default_json(struct bgp_path_attribute *pa) {
    return json_object();
}

void pa_default_free(struct bgp_path_attribute *pa) { }


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

    octets[3] = (uint8_t) ((ipv4 & 0xff000000) >> 24);
    octets[2] = (uint8_t) ((ipv4 & 0x00ff0000) >> 16);
    octets[1] = (uint8_t) ((ipv4 & 0x0000ff00) >> 8);
    octets[0] = (uint8_t) (ipv4 & 0x000000ff);

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
 * ORIGIN path attribute
 */

int pa_origin(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t length) {
    pa->origin = uchar_to_uint8_inc(pos);

    return 0;
}

json_t *pa_origin_json(struct bgp_path_attribute *pa) {
    json_t *origin = json_object();
    char *origin_string[] = {
        "IGP",
        "EGP",
        "Incomplete"
    };

    if (pa->origin > 2) {
        return json_object();
    }

    json_object_set_new( origin, "origin", json_string(origin_string[ pa->origin ]) );

    return origin;
}

/*
 * AS PATH
 */

enum bgp_asn_size {
    ASN_16,
    ASN_32,
};

//GCC thinks seg is leaked, but it's added to the as path segment and
//freed in free_as_path()
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
int __pa_as_path(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length, enum bgp_asn_size asn_size) {
    struct as_path *path;
    struct path_segment *seg;
    unsigned char **local_pos;
    uint16_t length;
    int n;

    local_pos = pos;
    //Remove two bytes to account or type and flags of the attrbute
    length = attr_length;

    path = calloc(1, sizeof(*path));    

    if (!path) {
        return -1;
    }

    path->n_segments = 0;
    path->n_total_as = 0;
    INIT_LIST_HEAD(&path->segments);

    //TODO: length sanity check
    while (length > 0) {
        seg = calloc(1, sizeof(*seg));
        
        if (!seg) {
            goto error;
        }

        INIT_LIST_HEAD(&seg->list);

        seg->type = uchar_to_uint8_inc(local_pos);
        //Number of ASes, not the number of bytes
        seg->n_as = uchar_to_uint8_inc(local_pos);
        length -= 2;

        if (length <= 0) {
            goto error;
        }

        seg->as = malloc(seg->n_as * sizeof(seg->as));

        if (!seg->as) {
            goto error;
        }

        //TODO: length check sanity
        for (n = 0; n < seg->n_as; n++) {
            //The seg->as[n] is a uint32_t and holds either the 16 or 32 bit ASNs
            switch (asn_size) {
                case ASN_16:
                    seg->as[n] = uchar_be_to_uint16_inc(local_pos);
                    length -= 2;
                    break;
                case ASN_32:
                    seg->as[n] = uchar_be_to_uint32_inc(local_pos);
                    length -= 4;
                    break;
                default:
                    return -1;
            }
        }

        list_add_tail(&seg->list, &path->segments);
        path->n_segments++;
        path->n_total_as += seg->n_as;

        seg = NULL;
    }

    pa->as_path = path;
    return 0;

    error:
    free(seg);
    free(path);
    return -1;

}
#pragma GCC diagnostic pop

int pa_as_16_path(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    return __pa_as_path(pa, pos, attr_length, ASN_16);
}

int pa_as_32_path(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    return __pa_as_path(pa, pos, attr_length, ASN_32);
}

json_t *pa_as_path_json(struct bgp_path_attribute *pa) {
    struct path_segment *seg;
    struct list_head *i;
    json_t *as_path = json_object();

    char *as_type_id_to_name[] = {
        "<Invalid>",
        "AS_SET",
        "AS_SEQUENCE"
    };

    if (!pa->as_path) {
        return json_object();
    }

    json_object_set_new( as_path, "n_as_segments", json_integer(pa->as_path->n_segments) );
    json_object_set_new( as_path, "n_total_as", json_integer(pa->as_path->n_total_as) );

    json_t *path_segments = json_array();
    list_for_each(i, &pa->as_path->segments) {
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


void pa_as_path_free(struct bgp_path_attribute *pa) {
    struct list_head *i, *tmp;
    struct path_segment *segment;

//GCC thinks free(segment->as) is a double free. I do not believe that's the case
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-double-free"
    list_for_each_safe(i, tmp, &pa->as_path->segments) {
        segment = list_entry(i, struct path_segment, list);
        list_del(i);
        free(segment->as);
        free(segment);
    }
#pragma GCC diagnostic pop
    
    free(pa->as_path);
}


/*
 * NEXTHOP
 */

int pa_nexthop(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    pa->next_hop = uchar_be_to_uint32_inc(pos);
    return 0;
}


json_t *pa_nexthop_json(struct bgp_path_attribute *pa) {
    json_t *nh = json_object();
    char *nh_str = ipv4_string(pa->next_hop);
    json_object_set_new(nh, "next_hop", json_string(nh_str) );
    free(nh_str);

    return nh;
}

/*
 * MULTI EXIT DISCRIMINATOR
 */
int pa_med(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    pa->multi_exit_disc = uchar_be_to_uint32_inc(pos);
    return 0;
}

json_t *pa_med_json(struct bgp_path_attribute *pa) {
    json_t *med = json_object();
    json_object_set_new( med, "med", json_integer(pa->multi_exit_disc) );
    return med;
}

/*
 * LOCAL PREFERENCE
 */
int pa_local_pref(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    pa->next_hop = uchar_be_to_uint32_inc(pos);
    return 0;
}

json_t *pa_local_pref_json(struct bgp_path_attribute *pa) {
    json_t *local_pref = json_object();
    json_object_set_new( local_pref, "local_pref", json_integer(pa->local_pref) );
    return local_pref;
}


/*
 * ATOMIC AGGREGATE
 *
 * Has a length of zero, so the type is enough to define this. The default
 * parsers are enough for this attribute
 */



/*
 * AGGREGATOR
 */

int __pa_aggregator(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length, enum bgp_asn_size asn_size) {
    struct aggregator *agg;
    unsigned char **local_pos;

    local_pos = pos;

    agg = calloc(1, sizeof(*agg));

    if (!agg) {
        return -1;
    }

    switch (asn_size) {
        case ASN_16:
            agg->asn = uchar_be_to_uint16_inc(local_pos);
            break;
        case ASN_32:
            printf("%x %x %x %x\n", **local_pos, *(*local_pos + 1), *(*local_pos+2), *(*local_pos+3));
            printf("%u\n", uchar_be_to_uint32(*local_pos));
            agg->asn = uchar_be_to_uint32_inc(local_pos);
            break;
        default:
            free(agg);
            return -1;
    }


    agg->ip = uchar_be_to_uint32_inc(local_pos);

    pa->aggregator = agg;

    return 0;
}

int pa_aggregator_16(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    return __pa_aggregator(pa, pos, attr_length, ASN_16);
}

int pa_aggregator_32(struct bgp_path_attribute *pa, unsigned char **pos, uint16_t attr_length) {
    return __pa_aggregator(pa, pos, attr_length, ASN_32);
}

json_t *pa_aggregator_json(struct bgp_path_attribute *pa) {
    json_t *aggregator = json_object();
    char *agg_ip_str = ipv4_string(pa->aggregator->ip);

    json_object_set_new( aggregator, "aggregator_asn", json_integer(pa->aggregator->asn) );
    json_object_set_new( aggregator, "aggregator_ip", json_string(agg_ip_str) );

    free(agg_ip_str);

    return aggregator;
}


void pa_aggregator_free(struct bgp_path_attribute *pa) {
    free(pa->aggregator);
}


/*
 * Initialisation of the path attribute dispatch table
 */
int init_pa_dispatch(void) {
    pa_dispatch = calloc(256, sizeof(struct path_attr_funcs));

    if (!pa_dispatch) {
        return -1;
    }

    //Set all path attributes to the unparsed functions
    for (int x = 0; x < 256; x++) {
        pa_dispatch[x].parse = &pa_default;
        pa_dispatch[x].json = &pa_default_json;
        pa_dispatch[x].free = &pa_default_free;
    }

    pa_dispatch[ORIGIN].parse = &pa_origin;
    pa_dispatch[ORIGIN].json = &pa_origin_json;
    pa_dispatch[AS_PATH].parse = &pa_as_16_path;
    pa_dispatch[AS_PATH].json = &pa_as_path_json;
    pa_dispatch[AS_PATH].free = &pa_as_path_free;
    pa_dispatch[NEXT_HOP].parse = &pa_nexthop;
    pa_dispatch[NEXT_HOP].json = &pa_nexthop_json;
    pa_dispatch[MULTI_EXIT_DISC].parse = &pa_med;
    pa_dispatch[MULTI_EXIT_DISC].json = &pa_med_json;
    pa_dispatch[LOCAL_PREF].parse = &pa_local_pref;
    pa_dispatch[LOCAL_PREF].json = &pa_local_pref_json;
    pa_dispatch[AGGREGATOR].parse = &pa_aggregator_16;
    pa_dispatch[AGGREGATOR].json = &pa_aggregator_json;
    pa_dispatch[AGGREGATOR].free = &pa_aggregator_free;

    pa_dispatch[AS4_PATH].parse = &pa_as_32_path;
    pa_dispatch[AS4_PATH].json = &pa_as_path_json;
    pa_dispatch[AS4_PATH].free = &pa_as_path_free;
    pa_dispatch[AS4_AGGREGATOR].parse = &pa_aggregator_32;
    pa_dispatch[AS4_AGGREGATOR].json = &pa_aggregator_json;
    pa_dispatch[AS4_AGGREGATOR].free = &pa_aggregator_free;

    return 0;
}
