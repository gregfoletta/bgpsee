#include <stdint.h>

#include "list.h"
#include "jansson.h"

struct as_path;
struct aggregator;

struct bgp_path_attribute {
    uint8_t flags;
    uint8_t type;
    //16 bits covers standard and extended length;
    uint16_t length;
    union {
        char *unparsed_value;
        uint8_t origin;
        struct as_path *as_path;
        uint32_t next_hop;
        uint32_t multi_exit_disc;
        uint32_t local_pref;
        //Atomic aggregate is length zero, defined only by the type
        struct aggregator *aggregator;
    }; 
};
//Holds pointers to functions for tasks related to the path attributes. 
//Used in an array indexed by the path attribute type
struct path_attr_funcs {
    int (*parse) (struct bgp_path_attribute *, unsigned char **, uint16_t);
    json_t *(*json) (struct bgp_path_attribute *);
    void (*free) (struct bgp_path_attribute *);
};

int init_pa_dispatch(void);
struct path_attr_funcs get_path_attr_dispatch(uint8_t);


/*
 UPDATE message and its dependencies
 https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
*/

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


