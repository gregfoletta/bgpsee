#include <stdlib.h>
#include <sys/socket.h>
#include <stddef.h>
#include <string.h>
#include <math.h>

#include "debug.h"
#include "bgp_message.h"
#include "bgp_capability.h"
#include "byte_conv.h"
#include "list.h"
#include "log.h"

#define BGP_HEADER_LEN 19 
#define BGP_HEADER_MARKER_LEN 16 
#define BGP_OPEN_HEADER_LEN 10 
//First byte after BGP header, same as length of header. 
#define BGP_MAX_LEN 4096 

//#define MSG_LENGTH(x) (uchar_be_to_uint16(x->raw + BGP_HEADER_MARKER_LEN)) //Length is the first two bytes after the marker
//#define MSG_TYPE(x) (uchar_to_uint8(x->raw + BGP_HEADER_MARKER_LEN + 2)) //Type is the next byte after the length


//Index matches the BGP message code
char *bgp_msg_code[] = {
    "<Reserved>",
    "OPEN",
    "UPDATE", 
    "NOTIFICATION",
    "KEEPALIVE",
    "ROUTE-REFRESH"
};

//Index matches the path attribute code
char *pa_type_code[] = {
    "<Reserved>",
    "ORIGIN",
    "AS_PATH",
    "NEXT_HOP",
    "MULTI_EXIT_DISC",
    "LOCAL_PREF",
    "ATOMIC_AGGREGATE",
    "AGGREGATOR"
};

struct bgp_msg_open_param {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
};


//Non-public functions
int validate_header(unsigned char *, struct bgp_msg *);
struct bgp_msg *alloc_bgp_msg(const uint16_t length, enum bgp_msg_type type);


int parse_open(struct bgp_msg *, unsigned char *);
int parse_update(struct bgp_msg *, unsigned char *);
int parse_keepalive(struct bgp_msg *);
int parse_notification(struct bgp_msg *, unsigned char *);
int parse_route_refresh(struct bgp_msg *);


/*
    recv_msg:

    Returns:
        0: success
        -1: Could not allocate memory
        -2: recv() returned EOF or error
        -3: Could not validate BGP message header (either marker or type)
        -4: Invalid message type stored in message stucture
*/

//TODO: perhaps move or remove
#include <errno.h>

#define MSG_PAD 256

struct bgp_msg *recv_msg(int socket_fd) {
    struct bgp_msg *message;
    unsigned char *message_body = NULL;

    unsigned char header[BGP_HEADER_LEN];
    ssize_t ret;

    message = calloc(1, sizeof(*message));

    if (!message) {
        return NULL;
    }

    INIT_LIST_HEAD(&message->ingress);
    INIT_LIST_HEAD(&message->output);
    message->actioned = 0;

    message->recv_time = time(NULL);

    ret = recv(socket_fd, header, sizeof(header), MSG_WAITALL);
    if (ret <= 0) { //EOF or error - switch to IDLE, and (eventually) cleanup
        log_print(LOG_DEBUG, "recv() header returned %lu, errno: %s\n", ret, strerror(errno));
        free(message);
        message = NULL;
        goto exit;
    }

    if (validate_header(header, message) < 0) {
        free(message);
        message = NULL;
        goto exit;
    }

    //TODO: danger area. Let's put some more thought into making sure
    //we validate this length param, as we've got it directly from the
    //message body
    //We over allocate (header is included) to give us to breathing space
    //at the other end
    message_body = malloc(message->body_length + MSG_PAD);

    if (!message_body) {
        free(message);
        return NULL;
    }

    if (message->body_length > 0) {
        ret = recv(socket_fd, message_body, message->body_length, MSG_WAITALL);
        if (ret <= 0) { //EOF or error
            log_print(LOG_DEBUG, "recv() returned < 0, errno: %s\n", strerror(errno));
            free(message);
            free(message_body);
            return NULL;
        } 
    }

    switch (message->type) {
        case OPEN:
            ret = parse_open(message, message_body);
            break;
        case UPDATE:
            ret = parse_update(message, message_body);
            break;
        case NOTIFICATION:
            ret = parse_notification(message, message_body);
            break;
        case KEEPALIVE:
            ret = parse_keepalive(message);
            break;
        case ROUTE_REFRESH:
            ret = parse_route_refresh(message);
            break;
        default:
            log_print(LOG_DEBUG, "Invalid message type stored in message structure: %d\n", message->type);
            free(message);
            free(message_body);
            return NULL;
    }

    if (ret < 0) {
        free(message);
        free(message_body);
        return NULL;
    }

exit:

    //Everything has been copied into the struct
    if (message_body) {
        free(message_body);
    }

    return message;
}

struct bgp_msg *alloc_sent_msg(void) {
    struct bgp_msg *message;

    message = calloc(1, sizeof(*message));

    if (!message) {
        return NULL;
    }

    INIT_LIST_HEAD(&message->ingress);
    INIT_LIST_HEAD(&message->output);
    message->actioned = 1;  // No FSM processing needed for sent messages
    message->recv_time = time(NULL);

    return message;
}

int free_update(struct bgp_update *);
int free_path_attributes(struct bgp_update *);
int free_as_path(struct bgp_path_attribute *);
int free_aggregator(struct bgp_path_attribute *);

int free_msg(struct bgp_msg *message) {
    switch (message->type) {
        case UPDATE:
            free_update(message->update);
            break;
    }

    free(message);
    return 0;
}


int free_update(struct bgp_update *update) {
    struct list_head *i, *tmp;
    struct ipv4_nlri *nlri;

    //Free withdrawn NLRI
    list_for_each_safe(i, tmp, &update->withdrawn_routes) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        list_del(i);
        free(nlri);
    }

    //Free advertised NLRI
    list_for_each_safe(i, tmp, &update->nlri) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        list_del(i);
        free(nlri);
    }

    free_path_attributes(update);
    free(update);
    return 0;
}

int free_path_attributes(struct bgp_update *update) {

    //Dispatch table
    int (*pa_free_dispatch[MAX_ATTRIBUTE + 1]) (struct bgp_path_attribute *);
    memset(pa_free_dispatch, 0, sizeof(pa_free_dispatch));

    pa_free_dispatch[AS_PATH] = &free_as_path;
    pa_free_dispatch[AGGREGATOR] = &free_aggregator;

    //Note the <=
    for (int attr = ORIGIN; attr <= MAX_ATTRIBUTE; attr++) {
        if (!update->path_attrs[ attr ]) {
            continue;
        }

        //If available, dispatch to the specific parameter free function
        if (pa_free_dispatch[ attr ]) {
            pa_free_dispatch[ attr ]( update->path_attrs[ attr ] );
        }

        //Free the parameter, which may have had its internals been freed above, or may be
        //an unparsed but allocated attribute
        free(update->path_attrs[ attr ]);
    }

    return 0;
}

int free_as_path(struct bgp_path_attribute *attribute) {
    struct list_head *i, *tmp;
    struct path_segment *segment;

    list_for_each_safe(i, tmp, &attribute->as_path->segments) {
        segment = list_entry(i, struct path_segment, list);
        list_del(i);
        free(segment->as);
        free(segment);
    }
    
    free(attribute->as_path);

    return 0;
}


int free_aggregator(struct bgp_path_attribute *attribute) {
    free(attribute->aggregator); 

    return 0;
}
    


int validate_header(unsigned char *header, struct bgp_msg *message) {
    uint16_t len;
    uint8_t type;
    unsigned char *pos;
    const unsigned char marker[] = { 
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
    };

    //Check that the marker is correct
    if(memcmp(header, marker, BGP_HEADER_MARKER_LEN)) {
        log_print(LOG_DEBUG, "Message has invalid marker\n");
        return -1;
    }

    //Pull out the type and length (single bytes, so no byte ordering issues)
    pos = header + sizeof(marker);

    len = uchar_be_to_uint16_inc(&pos);
    if (len < BGP_HEADER_LEN) {
        return -1;
    }

    type = *pos++;
    if (type == 0 || type > ROUTE_REFRESH) {
        log_print(LOG_DEBUG, "Received invalid message type: %d\n", type);
        return -1;
    }

    //Set the message and type
    message->type = type;
    message->length = len;
    message->body_length = len - BGP_HEADER_LEN;

    return 0;
}

#define BGP_HEADER_LENGTH 19
//Open header with no optional parameters
#define BGP_OPEN_HEADER_LENGTH BGP_HEADER_LENGTH + 10
#define BGP_MAX_MESSAGE_SIZE 4096


void create_header(uint16_t length, uint8_t type, unsigned char *message_buffer) {
    unsigned char *pos;
    const unsigned char marker[] = { 
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
    };

    memcpy(message_buffer, marker, sizeof(marker));
    pos = message_buffer + sizeof(marker);
    uint16_to_uchar_be_inc(&pos, length);
    uint8_to_uchar(pos, type);
}

int parse_open(struct bgp_msg *message, unsigned char *body) {
    message->open.version = *body++;
    message->open.asn = uchar_be_to_uint16_inc(&body);
    message->open.hold_time = uchar_be_to_uint16_inc(&body);
    message->open.router_id = uchar_be_to_uint32_inc(&body);
    message->open.opt_param_len = *body++;

    log_print(LOG_DEBUG, "Received OPEN message: V: %d, ASN: %d;, HT: %d, RID: %d, OPT_LEN: %d\n",
        message->open.version,
        message->open.asn,
        message->open.hold_time,
        message->open.router_id,
        message->open.opt_param_len
    );
        
    //TODO: OPEN message checks

    return 0;
}


ssize_t send_open(int fd, uint8_t version, uint16_t asn, uint16_t hold_time,
                  uint32_t router_id, const struct bgp_capabilities *caps) {
    unsigned char message_buffer[BGP_MAX_MESSAGE_SIZE];
    unsigned char *pos;
    uint8_t opt_param_len = 0;
    uint16_t total_length;
    int caps_encoded = 0;

    pos = message_buffer + BGP_HEADER_LENGTH;

    uint8_to_uchar_inc(&pos, version);
    uint16_to_uchar_be_inc(&pos, asn);
    uint16_to_uchar_be_inc(&pos, hold_time);
    uint32_to_uchar_be_inc(&pos, router_id);

    /* Reserve space for opt_param_len, we'll fill it in after encoding caps */
    unsigned char *opt_param_len_pos = pos;
    pos++;

    /* Encode capabilities if provided */
    if (caps && caps->count > 0) {
        size_t remaining = BGP_MAX_MESSAGE_SIZE - (size_t)(pos - message_buffer);
        caps_encoded = bgp_capabilities_encode(caps, pos, remaining);
        if (caps_encoded > 0) {
            opt_param_len = (uint8_t)caps_encoded;
            pos += caps_encoded;
        }
    }

    /* Write the opt_param_len */
    uint8_to_uchar(opt_param_len_pos, opt_param_len);

    /* Calculate total message length */
    total_length = (uint16_t)(pos - message_buffer);

    create_header(total_length, OPEN, message_buffer);

    return send(fd, message_buffer, total_length, 0);
}


//GCC thinks seg is leaked, but it's added to the as path segment and
//freed in free_as_path()
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
struct as_path *parse_update_as_path(unsigned char **body, uint16_t attr_length) {
    struct as_path *path;
    struct path_segment *seg;
    unsigned char **pos;
    uint16_t length;
    int n;

    pos = body;
    //Remove two bytes to account or type and flags of the attrbute
    length = attr_length;

    path = calloc(1, sizeof(*path));    

    if (!path) {
        return NULL;
    }

    path->n_segments = 0;
    path->n_total_as = 0;
    INIT_LIST_HEAD(&path->segments);

    while (length >= 2) {
        seg = calloc(1, sizeof(*seg));

        if (!seg) {
            goto error;
        }

        INIT_LIST_HEAD(&seg->list);

        seg->type = uchar_to_uint8_inc(pos);
        //Number of ASes, not the number of bytes
        seg->n_as = uchar_to_uint8_inc(pos);
        length -= 2;

        //Validate segment type (1=AS_SET, 2=AS_SEQUENCE)
        if (seg->type == 0 || seg->type > 2) {
            goto error;
        }

        //Check we have enough data for all AS numbers (2 bytes each)
        uint16_t as_bytes_needed = (uint16_t)seg->n_as * 2;
        if (as_bytes_needed > length) {
            goto error;
        }

        if (seg->n_as > 0) {
            seg->as = malloc(seg->n_as * sizeof(*seg->as));

            if (!seg->as) {
                goto error;
            }

            for (n = 0; n < seg->n_as; n++) {
                seg->as[n] = uchar_be_to_uint16_inc(pos);
            }
            length -= as_bytes_needed;
        }

        list_add_tail(&seg->list, &path->segments);
        path->n_segments++;
        path->n_total_as += seg->n_as;

        seg = NULL;
    }

    return path;

    error:
    free(seg);
    free(path);
    return NULL;

}
#pragma GCC diagnostic pop

struct aggregator *parse_update_aggregator(unsigned char **body) {
    struct aggregator *agg;
    unsigned char **pos;

    pos = body;

    agg = calloc(1, sizeof(*agg));

    if (!agg) {
        return NULL;
    }

    agg->asn = uchar_be_to_uint16_inc(pos);
    agg->ip = uchar_be_to_uint32_inc(pos);

    return agg;
}



struct bgp_path_attribute *parse_update_attr(unsigned char **body) {
    unsigned char **pos = body;
    struct bgp_path_attribute *attr;

    attr = calloc(1, sizeof(*attr));

    if (!attr) {
        return NULL;
    }

    attr->flags = uchar_to_uint8_inc(pos);
    attr->type = uchar_to_uint8_inc(pos);

    
    //One or two octet length?
    if (attr->flags & 0x16) {
        attr->length = uchar_be_to_uint16_inc(pos);
    } else {
        attr->length = uchar_to_uint8_inc(pos);
    }

    switch (attr->type) {
        case ORIGIN:
            attr->origin = uchar_to_uint8_inc(pos);
            break;
        case AS_PATH:
            if (attr->length > 0) {
                attr->as_path = parse_update_as_path(pos, attr->length);
            }
            break;
        case NEXT_HOP:
            attr->next_hop = uchar_be_to_uint32_inc(pos);
            break;
        case MULTI_EXIT_DISC:
            attr->multi_exit_disc = uchar_be_to_uint32_inc(pos);
            break;
        case LOCAL_PREF:
            attr->local_pref = uchar_be_to_uint32_inc(pos);
            break;
        case ATOMIC_AGGREGATE:
            //Length of zero, type is enough to define this
            break;
        case AGGREGATOR:
            attr->aggregator = parse_update_aggregator(pos);
            break;
        default:
            //Skip over the top of the attribute
            *pos += attr->length;
    }

    return attr;
}

struct ipv4_nlri *parse_ipv4_nlri(unsigned char **body) {
    unsigned char **pos = body;
    struct ipv4_nlri *nlri = NULL;

    nlri = calloc(1, sizeof(*nlri));
    if (!nlri) {
        return NULL;
    }


    INIT_LIST_HEAD(&nlri->list);

    nlri->length = uchar_to_uint8_inc(pos);
    //Fast ceil(length / 8)
    nlri->bytes = (uint8_t) (nlri->length + 8 - 1) / 8;

    //IPv4 prefix cannot exceed 32 bits (4 bytes)
    if (nlri->bytes > 4) {
        free(nlri);
        return NULL;
    }

    for (int x = 0; x < nlri->bytes; x++) {
        nlri->prefix[x] = uchar_to_uint8_inc(pos);
    }

    snprintf(
        nlri->string,
        MAX_IPV4_ROUTE_STRING,
        "%d.%d.%d.%d/%d",
        nlri->prefix[0], nlri->prefix[1], nlri->prefix[2], nlri->prefix[3], nlri->length
    );



    return nlri;
}


int parse_update(struct bgp_msg *message, unsigned char *body) {
    unsigned char *pos = body;
    struct ipv4_nlri *nlri;

    log_print(LOG_DEBUG, "Received UPDATE\n");

    message->update = calloc(1, sizeof(*message->update));

    if (!message->update) {
        return -1;
    }

    INIT_LIST_HEAD(&message->update->withdrawn_routes);
    INIT_LIST_HEAD(&message->update->nlri);

    //body_length is message->length - 19 (BGP header)
    //UPDATE body has: 2 bytes withdrawn_len + withdrawn + 2 bytes pa_len + pa + nlri
    //Minimum UPDATE body is 4 bytes (two length fields)
    if (message->body_length < 4) {
        free(message->update);
        return -1;
    }

    message->update->withdrawn_route_length = uchar_be_to_uint16_inc(&pos);

    //Validate withdrawn_route_length fits in remaining body
    //Remaining after withdrawn_len field: body_length - 2
    //Need: withdrawn_route_length + 2 (path_attr_length field)
    if (message->update->withdrawn_route_length > message->body_length - 4) {
        free(message->update);
        return -1;
    }

    //Parse withdrawn routes
    if (message->update->withdrawn_route_length > 0) {
        unsigned char *withdrawn_end = pos + message->update->withdrawn_route_length;

        while (pos < withdrawn_end) {
            nlri = parse_ipv4_nlri(&pos);
            if (!nlri) {
                break;
            }

            list_add_tail(&nlri->list, &message->update->withdrawn_routes);
        }
    }

    //Parse the path attributes
    message->update->path_attr_length = uchar_be_to_uint16_inc(&pos);

    //Validate path_attr_length fits in remaining body
    //Used so far: 2 + withdrawn_route_length + 2 = 4 + withdrawn_route_length
    uint32_t used = 4 + message->update->withdrawn_route_length;
    if (message->update->path_attr_length > message->body_length - used) {
        free(message->update);
        return -1;
    }

    if (message->update->path_attr_length > 0) {
        unsigned char *pa_start = pos;
        struct bgp_path_attribute *attr;
        int n_attr = 0;

        while(pos < (pa_start + message->update->path_attr_length)) {
            attr = parse_update_attr(&pos);

            if (!attr) {
                free(message->update);
                return -1;
            }

            message->update->path_attrs[ attr->type ] = attr;
            n_attr++;
        }
    }

    //NLRI information - remaining bytes after withdrawn routes and path attributes
    //body_length - 4 (length fields) - withdrawn_route_length - path_attr_length
    uint32_t total_used = 4 + message->update->withdrawn_route_length + message->update->path_attr_length;
    if (total_used > message->body_length) {
        free(message->update);
        return -1;
    }
    uint16_t nlri_length = message->body_length - (uint16_t)total_used;
    unsigned char *nlri_end = pos + nlri_length;

    while (pos < nlri_end) {
        nlri = parse_ipv4_nlri(&pos);
        if (!nlri) {
            break;
        }
        list_add_tail(&nlri->list, &message->update->nlri);
    }

    return 0;
}



int parse_notification(struct bgp_msg *message, unsigned char *body) {
    message->notification.code = *body++;
    message->notification.subcode = *body;

    log_print(LOG_DEBUG, "Received NOTIFICATION message: Code: %d, Subcode: %d\n",
        message->notification.code,
        message->notification.subcode
    );

    return 0;
}

//This function is essentially a NOOP, as the header has already been parsed,
//and a keepalive has no message body
int parse_keepalive(struct bgp_msg *message) {
    log_print(LOG_DEBUG, "Received KEEPALIVE message (%d, %d, %d)\n",
        message->type,
        message->length,
        message->body_length
    );

    return 0;
}


ssize_t send_keepalive(int fd) {
    //Keepalive consists only of the BGP header
    unsigned char message_buffer[BGP_HEADER_LENGTH];

    create_header(BGP_HEADER_LENGTH, KEEPALIVE, message_buffer);

    return send(fd, message_buffer, BGP_HEADER_LENGTH, 0);
}

#define BGP_NOTIFICATION_HEADER_LENGTH (BGP_HEADER_LENGTH + 2)

ssize_t send_notification(int fd, uint8_t code, uint8_t subcode) {
    unsigned char message_buffer[BGP_NOTIFICATION_HEADER_LENGTH];
    unsigned char *pos;

    create_header(BGP_NOTIFICATION_HEADER_LENGTH, NOTIFICATION, message_buffer);

    pos = message_buffer + BGP_HEADER_LENGTH;
    uint8_to_uchar_inc(&pos, code);
    uint8_to_uchar_inc(&pos, subcode);

    log_print(LOG_DEBUG, "Sending NOTIFICATION: code=%d, subcode=%d\n", code, subcode);

    return send(fd, message_buffer, BGP_NOTIFICATION_HEADER_LENGTH, 0);
}

int parse_route_refresh(struct bgp_msg *message) {
    return 0;

}
