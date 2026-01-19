#include <stdlib.h>
#include <string.h>

#include "bgp_capability.h"
#include "byte_conv.h"

/* Optional Parameter Type for Capabilities (RFC 5492) */
#define BGP_OPT_PARAM_CAPABILITIES 2

struct bgp_capabilities *bgp_capabilities_create(void) {
    struct bgp_capabilities *caps;

    caps = calloc(1, sizeof(*caps));
    if (!caps) {
        return NULL;
    }

    caps->count = 0;
    caps->total_length = 0;
    INIT_LIST_HEAD(&caps->caps);

    return caps;
}

void bgp_capabilities_free(struct bgp_capabilities *caps) {
    struct list_head *pos, *tmp;
    struct bgp_capability *cap;

    if (!caps) {
        return;
    }

    list_for_each_safe(pos, tmp, &caps->caps) {
        cap = list_entry(pos, struct bgp_capability, list);
        list_del(pos);
        free(cap->value);
        free(cap);
    }

    free(caps);
}

/*
 * GCC analyzer warning suppression: analyzer cannot track ownership transfer
 * through linked list. Memory is freed by bgp_capabilities_free().
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
int bgp_capabilities_add(struct bgp_capabilities *caps,
                         uint8_t code, uint8_t length, const uint8_t *value) {
    struct bgp_capability *cap;

    if (!caps) {
        return -1;
    }

    cap = calloc(1, sizeof(*cap));
    if (!cap) {
        return -1;
    }

    cap->code = code;
    cap->length = length;
    cap->value = NULL;
    INIT_LIST_HEAD(&cap->list);

    if (length > 0 && value) {
        cap->value = malloc(length);
        if (!cap->value) {
            free(cap);
            return -1;
        }
        memcpy(cap->value, value, length);
    }

    list_add_tail(&cap->list, &caps->caps);
    caps->count++;
    /* Each capability: code (1) + length (1) + value (length) */
    caps->total_length += 2 + length;

    return 0;
}
#pragma GCC diagnostic pop

int bgp_capabilities_add_route_refresh(struct bgp_capabilities *caps) {
    return bgp_capabilities_add(caps, BGP_CAP_ROUTE_REFRESH, 0, NULL);
}

int bgp_capabilities_add_four_octet_asn(struct bgp_capabilities *caps, uint32_t asn) {
    uint8_t value[4];

    uint32_to_uchar_be(value, asn);
    return bgp_capabilities_add(caps, BGP_CAP_FOUR_OCTET_ASN, 4, value);
}

int bgp_capabilities_add_mp_ext(struct bgp_capabilities *caps,
                                uint16_t afi, uint8_t safi) {
    uint8_t value[4];

    /* AFI (2 bytes) + Reserved (1 byte) + SAFI (1 byte) */
    uint16_to_uchar_be(value, afi);
    value[2] = 0;  /* Reserved */
    value[3] = safi;

    return bgp_capabilities_add(caps, BGP_CAP_MP_EXT, 4, value);
}

int bgp_capabilities_encode(const struct bgp_capabilities *caps,
                            unsigned char *buf, size_t buf_size) {
    struct list_head *pos;
    struct bgp_capability *cap;
    unsigned char *ptr;
    size_t required_size;

    if (!caps || !buf) {
        return -1;
    }

    if (caps->count == 0) {
        return 0;
    }

    /* Need space for: param_type (1) + param_len (1) + capabilities */
    required_size = 2 + caps->total_length;
    if (buf_size < required_size) {
        return -1;
    }

    ptr = buf;

    /* Optional Parameter header */
    *ptr++ = BGP_OPT_PARAM_CAPABILITIES;  /* Parameter Type */
    *ptr++ = (uint8_t)caps->total_length; /* Parameter Length */

    /* Encode each capability */
    list_for_each(pos, &caps->caps) {
        cap = list_entry(pos, struct bgp_capability, list);

        *ptr++ = cap->code;
        *ptr++ = cap->length;

        if (cap->length > 0 && cap->value) {
            memcpy(ptr, cap->value, cap->length);
            ptr += cap->length;
        }
    }

    return (int)(ptr - buf);
}

struct bgp_capabilities *bgp_capabilities_parse(const unsigned char *opt_params,
                                                 uint8_t opt_param_len) {
    struct bgp_capabilities *caps;
    const unsigned char *ptr;
    const unsigned char *end;

    if (!opt_params && opt_param_len > 0) {
        return NULL;
    }

    caps = bgp_capabilities_create();
    if (!caps) {
        return NULL;
    }

    if (opt_param_len == 0) {
        return caps;
    }

    ptr = opt_params;
    end = opt_params + opt_param_len;

    /* Parse optional parameters */
    while (ptr < end) {
        uint8_t param_type;
        uint8_t param_len;
        const unsigned char *param_end;

        /* Need at least 2 bytes for type and length */
        if (ptr + 2 > end) {
            break;
        }

        param_type = *ptr++;
        param_len = *ptr++;
        param_end = ptr + param_len;

        /* Validate parameter doesn't exceed buffer */
        if (param_end > end) {
            break;
        }

        /* Only parse Capabilities parameter (type 2) */
        if (param_type == BGP_OPT_PARAM_CAPABILITIES) {
            /* Parse capabilities within this parameter */
            while (ptr < param_end) {
                uint8_t cap_code;
                uint8_t cap_len;

                /* Need at least 2 bytes for code and length */
                if (ptr + 2 > param_end) {
                    break;
                }

                cap_code = *ptr++;
                cap_len = *ptr++;

                /* Validate capability doesn't exceed parameter */
                if (ptr + cap_len > param_end) {
                    break;
                }

                /* Add capability to list */
                bgp_capabilities_add(caps, cap_code, cap_len, cap_len > 0 ? ptr : NULL);
                ptr += cap_len;
            }
        } else {
            /* Skip unknown parameter types */
            ptr = param_end;
        }
    }

    return caps;
}

const char *bgp_capability_name(uint8_t code) {
    switch (code) {
        case BGP_CAP_MP_EXT:           return "Multiprotocol Extensions";
        case BGP_CAP_ROUTE_REFRESH:    return "Route Refresh";
        case BGP_CAP_ORF:              return "Outbound Route Filtering";
        case BGP_CAP_EXTENDED_NEXTHOP: return "Extended Next Hop Encoding";
        case BGP_CAP_EXTENDED_MESSAGE: return "BGP Extended Message";
        case BGP_CAP_GRACEFUL_RESTART: return "Graceful Restart";
        case BGP_CAP_FOUR_OCTET_ASN:   return "4-octet AS Number";
        case BGP_CAP_ADD_PATH:         return "ADD-PATH";
        case BGP_CAP_ENHANCED_REFRESH: return "Enhanced Route Refresh";
        case BGP_CAP_FQDN:             return "FQDN";
        default:                       return "Unknown";
    }
}
