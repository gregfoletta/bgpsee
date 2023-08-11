#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "bgp.h"
#include "bgp_cli.h"
#include "log.h"
#include "debug.h"

#include "sds.h"

#define BGP_V4 4
#define MAX_PEER_NAME_LEN 64

struct cmdline_opts {
    int option_index;
    enum LOG_LEVEL log_level;
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
    int bgp_peer_ids[MAX_BGP_PEERS];
    char read_buffer[32];

    memset(bgp_peer_ids, 0, sizeof(bgp_peer_ids));

    options = parse_cmdline(argc, argv);

    if (options.debug) {
        debug_enable();
    };

    set_log_level(options.log_level);

    if (optind >= argc) {
        log_print(LOG_ERROR, "No BGP peers specified\n");
        exit(1);
    }

    bgp_i = create_bgp_instance(options.local_asn, options.local_rid, BGP_V4);

    //Parse the peers
    for(int x = optind; x < argc; x++) {
        uint16_t asn;
        int bgp_peer_id;
        //Split the peer into IP:ASN
        sds *tokens;
        sds peer_name;
        int n_tokens;

        sds peer_arg = sdsnew(argv[x]);
        tokens = sdssplitlen(peer_arg, sdslen(peer_arg), ",", 1, &n_tokens);

        if (n_tokens > 3 || n_tokens < 2) {
            log_print(LOG_ERROR, "Incorrect peer format '%s'. Please use <ip>,<asn> or <ip>,<asn>,<name>\n", peer_arg);
            exit(1);
        }

        //If there's no name create a name based on the argc position
        if (n_tokens == 2) {
            peer_name = sdsnew("BGP_Peer_");
            peer_name = sdscatprintf(peer_name, "%d", x - optind);
        }

        if (n_tokens == 3) {
            peer_name = sdsdup(tokens[2]);
        }
        asn = (uint16_t) strtol(tokens[1], NULL, 10);

        //Create the peer and keep track of the used ID
        bgp_peer_id = create_bgp_peer(
            bgp_i,
            tokens[0],
            asn,
            peer_name
        );

        bgp_peer_ids[ bgp_peer_id ] = 1;

        sdsfree(peer_arg);
        sdsfree(peer_name);
        sdsfreesplitres(tokens, n_tokens);
    }

    free(options.name);

    for(int id = 0; id < MAX_BGP_PEERS; id++) {
        if (!bgp_peer_ids[id]) {
            continue;
        }

        if (activate_bgp_peer(bgp_i, id)) {
            fprintf(stderr, "- Could not activate peer (ID %d)\n", id);
        }
    }


    fprintf(stderr, "- Press Ctrl+D to exit\n");
    while (read(0, read_buffer, 32) > 0) { };
    fprintf(stderr, "- Closing...\n");

    deactivate_all_bgp_peers(bgp_i);
    free_all_bgp_peers(bgp_i);
    free_bgp_instance(bgp_i);

    return 0;
}



struct cmdline_opts parse_cmdline(int argc, char **argv) {
    static struct cmdline_opts option_return;
    int c;
    int *i;

    //Shortcut to the index in the struct
    i = &option_return.option_index;

    //Defaults
    option_return = (struct cmdline_opts) {
        .log_level = LOG_INFO,
        .peer = NULL,
        .peer_asn = 0,
        .local_asn = 65000,
        .local_rid = 0x01010101,
        .name = calloc(MAX_PEER_NAME_LEN, sizeof(char)) 
    };

    strncpy(option_return.name, "BGP Peer", MAX_PEER_NAME_LEN);

    static struct option cmdline_options[] = {
        { "local-asn", required_argument, 0, 'a' },
        { "local-rid", required_argument, 0, 'r' },
        { "level", required_argument, 0, 'l'},
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
            case 'a':
                option_return.local_asn = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'r':
                option_return.local_rid = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'l':
                option_return.log_level = (uint16_t) strtol(optarg, NULL, 10);
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
