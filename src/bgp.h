#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <pthread.h>

#include "bgp_common.h"
#include "bgp_print.h"


//Static number of BGP peers for the moment;
#define MAX_BGP_PEERS 256

/*
 * BGP OPEN Optional Parameters used in a bitfield
 * Index into the bitmask is defined by their capability's 
 * parameter type value.
 */
#define BGP_CAP_COMMUNITIES 1 << 8
#define BGP_CAP_EXTENDED_COMMUNITIES 1 << 16

struct bgp_peer;
struct bgp_instance;
struct bgp_local;

struct bgp_instance *create_bgp_instance(uint16_t,  uint32_t, uint8_t);
void free_bgp_instance(struct bgp_instance *);

unsigned int create_bgp_peer(struct bgp_instance *, const char *, const uint16_t, const char *);
unsigned int bgp_peer_source(struct bgp_instance *, unsigned int, const char *);

int set_bgp_output(struct bgp_instance *, unsigned int, enum bgp_output);

int set_bgp_capabilities(struct bgp_instance *, unsigned int, uint64_t);

void free_bgp_peer(struct bgp_instance *, unsigned int);
void free_all_bgp_peers(struct bgp_instance *);

int activate_bgp_peer(struct bgp_instance *, unsigned int);
int deactivate_bgp_peer(struct bgp_instance *, unsigned int);
int deactivate_all_bgp_peers(struct bgp_instance *);
