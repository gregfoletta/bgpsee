#include "bgp_peer.h"


void initialise_output(struct bgp_peer *peer);
void print_bgp_msg_and_gc(struct bgp_peer *);

void print_msg_stdout(struct bgp_msg *);
void print_msg_json(struct bgp_msg *);
