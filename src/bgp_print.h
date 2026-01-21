//Types of output
enum bgp_output {
    BGP_OUT_JSON,
    BGP_OUT_JSONL,
    N_BGP_FORMATS
} ;

struct bgp_peer;
struct bgp_msg;

void initialise_output(struct bgp_peer *) ;
int _set_bgp_output(struct bgp_peer *, enum bgp_output);

/* Format functions - return malloc'd string, caller must free */
char *format_msg_json(struct bgp_msg *);
char *format_msg_jsonl(struct bgp_msg *);

