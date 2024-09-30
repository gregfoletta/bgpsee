#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "byte_conv.h"

struct tlv {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
};


#include <stdio.h>
struct tlv *new_tlv(uint8_t type, uint8_t length, unsigned char *value) {
    int x;
    struct tlv *tlv;
    tlv = calloc(1, sizeof(*tlv));

    if(!tlv) {
        return NULL;
    }

    tlv->type = type;
    tlv->length = length;
    printf("new_tlv(): type: %d, len: %d\n", type, length);

    //If length is 0, no value
    if (length == 0) {
        tlv->value = NULL;
        return tlv;
    }
    //We do a copy of of value
    tlv->value = calloc(length, sizeof(*value));
    for (x = 0; x < length; x++) {
        printf("new_tlv(): value[x]: %d", value[x]);
        tlv->value[x] = value[x];
    }

    return tlv;
}

struct tlv *new_tlv_serialise(uint8_t type, uint8_t length, void *data, unsigned char * (*f)(void *)) {
    unsigned char *serialised;
    struct tlv *tlv;

    serialised = f(data);
    tlv = new_tlv(type, length, data);
    free(serialised);

    return tlv;
}


void free_tlv(struct tlv *tlv) {
    if (tlv->value) {
        free(tlv->value);
    }

    free(tlv);
}


unsigned char *serialise_tlv(struct tlv *tlv, uint8_t *len) {
    uint8_t x = 0;
    unsigned char *buffer = NULL, *buffer_start;

    *len = 0;

    buffer = calloc(2 + tlv->length, sizeof(*buffer));

    printf("serialise_tlv(): buffer: %p, tlv->length: %d, sizeof(*buffer): %ld\n", buffer, tlv->length, sizeof(*buffer));

    if (!buffer) {
        return NULL;
    }

    buffer_start = buffer;

    //Encode the type, length and increment total length
    uint8_to_uchar_inc(&buffer, tlv->type);
    uint8_to_uchar_inc(&buffer, tlv->length);
    *len += 2;
    
    printf("serialise_tlv(): len (1): %d\n", *len);

    //If the length is 0, return the T & L byte length
    if (tlv->length == 0) {
        return buffer_start;
    }

    for (x = 0; x < tlv->length; x++) {
        printf("here %d\n", x);
        uint8_to_uchar_inc(&buffer, tlv->value[x]);
    }
    
    printf("serialise_tlv(): len (2): %d\n", *len);

    *len += x;
    return buffer_start;
}
