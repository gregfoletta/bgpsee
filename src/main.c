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
    enum bgp_output output;
    char *peer;
    char *name;
    sds source_ip;
    uint32_t peer_asn;
    uint32_t local_asn;
    uint32_t local_rid;
    enum bgp_output format;
    int reconnect_enabled;
    int reconnect_max_retries;
    uint16_t hold_time;
    int _error;
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

    if (options._error) {
        log_print(LOG_ERROR, "Command line options error, exiting");
        exit(1);
    }

    set_log_level(options.log_level);

    if (optind >= argc) {
        log_print(LOG_ERROR, "No BGP peers specified\n");
        exit(1);
    }

    bgp_i = create_bgp_instance(options.local_asn, options.local_rid, BGP_V4);

    //Parse the peers
    for(int x = optind; x < argc; x++) {
        uint32_t asn;
        int bgp_peer_id;
        //Split the peer into IP:ASN
        sds *tokens;
        sds peer_name = NULL;
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
        asn = (uint32_t) strtoul(tokens[1], NULL, 10);

        //Create the peer and keep track of the used ID
        bgp_peer_id = create_bgp_peer(
            bgp_i,
            tokens[0],
            asn,
            peer_name
        );

        //Set the source address
        bgp_peer_source(bgp_i, bgp_peer_id, options.source_ip);
        //Set the logging output (global for all peers)
        set_bgp_output(bgp_i, bgp_peer_id, options.format);
        //Set reconnection settings
        set_bgp_reconnect(bgp_i, bgp_peer_id, options.reconnect_enabled, options.reconnect_max_retries);
        //Set hold time
        set_bgp_hold_time(bgp_i, bgp_peer_id, options.hold_time);

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
            log_print(LOG_ERROR, "Could not activate peer (ID %d)\n", id);
        }
    }


    log_print(LOG_INFO, "Press Ctrl+D to exit\n");
    while (read(0, read_buffer, 32) > 0) { };
    log_print(LOG_INFO, "Shutting down peers..\n");


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
        .source_ip = NULL,
        .log_level = LOG_INFO,
        .peer = NULL,
        .peer_asn = 0,
        .local_asn = 65000,
        .local_rid = 0x01010101,
        .format = BGP_OUT_JSON,
        .reconnect_enabled = 0,
        .reconnect_max_retries = 0,
        .hold_time = 600,
        .name = calloc(MAX_PEER_NAME_LEN, sizeof(char)),
        ._error = 0
    };

    if (!option_return.name) {
        option_return._error = 1;
        return option_return;

    }


    strncpy(option_return.name, "BGP Peer", MAX_PEER_NAME_LEN);

    static struct option cmdline_options[] = {
        { "source", required_argument, 0, 's' },
        { "asn", required_argument, 0, 'a' },
        { "rid", required_argument, 0, 'r' },
        { "logging", required_argument, 0, 'l'},
        { "format", required_argument, 0, 'f'},
        { "reconnect", no_argument, NULL, 'R'},
        { "max-retries", required_argument, NULL, 'm'},
        { "hold-time", required_argument, NULL, 't'},
        { "help", no_argument, NULL, 'h'},
        { 0, 0, 0, 0 }
    };

    char *out_fmts[] = { "json", "jsonl" };

    while (1) {
        c = getopt_long(argc, argv, "s:a:r:l:f:Rm:t:h", cmdline_options, i);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'h':
                print_help();
                exit(0);
            case 's':
                option_return.source_ip = sdsnew(optarg);
                break;
            case 'a':
                option_return.local_asn = (uint32_t) strtoul(optarg, NULL, 10);
                break;
            case 'r':
                option_return.local_rid = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'l':
                option_return.log_level = (uint16_t) strtol(optarg, NULL, 10);
                break;
            case 'f':
                for (int x = 0; x < N_BGP_FORMATS; x++) {
                    if (!strcmp(optarg, out_fmts[x])) {
                        option_return.format = x;
                    }
                }
                break;
            case 'R':
                option_return.reconnect_enabled = 1;
                break;
            case 'm':
                option_return.reconnect_max_retries = (int) strtol(optarg, NULL, 10);
                break;
            case 't':
                option_return.hold_time = (uint16_t) strtoul(optarg, NULL, 10);
                break;
        }
    }

    return option_return;
}


void print_help(void) {
    char *help_message = "Usage: bgpsee [options...] <peer> [<peer> ...]\n"
        "-s, --source <ip>\tIP to source BGP connection from\n"
        "-a, --asn <asn>\t\tLocal ASN (supports 4-byte ASNs). Default: 65000\n"
        "-r, --rid <ip>\t\tLocal router ID of bgpsee. If not provided 1.1.1.1 will be used.\n"
        "-l, --logging <level>\tLogging output level, 0: BGP messages only, 1: Errors, 2: Warnings, 3: Info (default), 4: Debug \n"
        "-f, --format <fmt>\tFormat of the output, <fmt> may be 'json' (pretty) or 'jsonl' (single line). Defaults to 'json'\n"
        "-R, --reconnect\t\tEnable automatic reconnection with exponential backoff\n"
        "-m, --max-retries <n>\tMaximum reconnection attempts (0 = infinite, default)\n"
        "-t, --hold-time <sec>\tBGP hold time in seconds (default: 600)\n"
        "-h, --help\t\tPrint this help message\n"
        "\n"
        "<peer> formats: <ip>,<asn> or <ip>,<asn>,<name>\n\n";


    printf("%s", help_message);
}
