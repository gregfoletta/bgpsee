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
