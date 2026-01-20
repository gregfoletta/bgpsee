//Types of output
enum bgp_output {
    BGP_OUT_JSON,
    BGP_OUT_JSONL,
    N_BGP_FORMATS
} ;

struct bgp_peer;

void initialise_output(struct bgp_peer *) ;
int _set_bgp_output(struct bgp_peer *, enum bgp_output);

