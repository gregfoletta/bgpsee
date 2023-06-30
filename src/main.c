#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "bgp.h"
#include "bgp_cli.h"
#include "debug.h"

#define BGP_V4 4
#define MAX_PEER_NAME_LEN 64

struct cmdline_opts {
    int option_index;
    int debug;
    char *peer;
    char *name;
    uint16_t peer_asn;
    uint16_t local_asn;
    uint32_t local_rid;
};

struct cmdline_opts parse_cmdline(int, char **);
void print_help(void);

int main(int argc, char **argv) {
    struct cmdline_opts options;
    struct bgp_instance *bgp_i = NULL;
    int bgp_peer_id;
    char read_buffer[32];

    options = parse_cmdline(argc, argv);

    if (options.debug) {
        debug_enable();
    };

    if (!options.peer) {
        fprintf(stderr, "Error: 'peer-ip' not set\n");
        return 1;
    }
    bgp_i = create_bgp_instance(options.local_asn, options.local_rid, BGP_V4);

    bgp_peer_id = create_bgp_peer(
        bgp_i,
        options.peer,
        options.peer_asn,
        options.name
    );

    free(options.name);

    if (activate_bgp_peer(bgp_i, bgp_peer_id)) {
        fprintf(stderr, "Could not activate peer (ID %d)\n", bgp_peer_id);
    }

    fprintf(stderr, "- Press Ctrl+D to exit\n");
    while (read(0, read_buffer, 32) > 0) { };
    fprintf(stderr, "- Closing...\n");

    deactivate_bgp_peer(bgp_i, bgp_peer_id);
    free_bgp_peer(bgp_i, bgp_peer_id);
    free_bgp_instance(bgp_i);

    return 0;
}



struct cmdline_opts parse_cmdline(int argc, char **argv) {
    static struct cmdline_opts option_return;
    size_t opt_len;
    int c;
    int *i;

    //Shortcut to the index in the struct
    i = &option_return.option_index;

    //Defaults
    option_return = (struct cmdline_opts) {
        .debug = 0,
        .peer = NULL,
        .peer_asn = 0,
        .local_asn = 65000,
        .local_rid = 0x01010101,
        .name = calloc(MAX_PEER_NAME_LEN, sizeof(char)) 
    };

    strncpy(option_return.name, "BGP Peer", MAX_PEER_NAME_LEN);

    static struct option cmdline_options[] = {
        { "peer-ip", required_argument, 0, 'p' },
        { "name", required_argument, 0, 'n' },
        { "peer-asn", required_argument, 0, 'a' },
        { "local-asn", required_argument, 0, 'l' },
        { "local-rid", required_argument, 0, 'r' },
        { "help", no_argument, NULL, 'h'},
        { "debug", no_argument, &option_return.debug, 1},
        { 0, 0, 0, 0 }
    };

    while (1) {
        c = getopt_long(argc, argv, "", cmdline_options, i);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'h':
                print_help();
                exit(0);
            case 'p':
                opt_len = strlen(optarg);
                option_return.peer = malloc( (sizeof(char) * opt_len) + 1 );
                strncpy(option_return.peer, optarg, opt_len + 1);
                option_return.peer[opt_len] = '\0';
                break;
            case 'a':
                option_return.peer_asn = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'l':
                option_return.local_asn = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'r':
                option_return.local_rid = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'n':
                strncpy(option_return.name, optarg, MAX_PEER_NAME_LEN);
                break;
        }
    }

    return option_return;
}


void print_help(void) {
    char *help_message = "Usage: bgpsee [params]\n"
        "\n"
        "foo";

    printf("%s", help_message);
}
