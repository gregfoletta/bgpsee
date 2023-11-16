#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "bgp_message.h"
#include "bgp_print.h"
#include "list.h"


/* NOTE:
 * The code in here is far from perfect, but gets the job done.
 * Please leave your judgement at the door
 */

void print_open(struct bgp_msg *);
void print_update(struct bgp_msg *);
void print_notification(struct bgp_msg *);
void print_keepalive(struct bgp_msg *);
void print_routerefresh(struct bgp_msg *);

void print_bgp_msg_and_gc(struct bgp_peer *peer) {
    struct bgp_msg *msg = NULL;
    struct list_head *i, *tmp;

    if (list_empty(&peer->output_q)) {
        return;
    }

    //Lock stdout
    pthread_mutex_lock(&peer->stdout_lock);

    list_for_each_safe(i, tmp, &peer->output_q) {
        msg = list_entry(i, struct bgp_msg, output);
        //Don't print of the message hasn't been actioned yet
        if (!msg->actioned) {
            return;
        }
        peer->print_msg(msg);
        list_del(i);
        free_msg(msg);
    }

    pthread_mutex_unlock(&peer->stdout_lock);
}


void print_msg_stdout(struct bgp_msg *msg) {
    void (*dispatch[5]) (struct bgp_msg *) = {
        &print_open,
        &print_update,
        &print_notification,
        &print_keepalive,
        &print_routerefresh,
    };

    //We've already done a check in recv_msg(), but better safe than sorry
    if (msg->type > 4) {
        return;
    }

    char *type_string[] = {
        "<NULL>",
        "OPEN",
        "UPDATE",
        "NOTIFICATON",
        "KEEPALIVE",
        "ROUTE-REFRESH"
    };

    printf("recv_time=%ld name=%s id=%ld type=%s length=%d ", msg->recv_time, msg->peer_name, msg->id, type_string[ msg->type ],  msg->length); 
    dispatch[msg->type - 1](msg);
}

void print_msg_json(struct bgp_msg *msg) {
    printf("Printing JSON\n");

}


void initialise_output(struct bgp_peer *peer) {
    pthread_mutex_lock(&peer->stdout_lock);

    peer->print_msg = print_msg_stdout;
}

void print_open(struct bgp_msg *msg) {
    printf(
        "version=%d, asn=%d, hold_time=%d, router_id=%d, param_len=%d\n",
        msg->open.version,
        msg->open.asn,
        msg->open.hold_time,
        msg->open.router_id,
        msg->open.opt_param_len
    );

    //TODO: parameters
}

void print_pa_origin(struct bgp_path_attribute *pa) {
    char *origin_string[] = {
        "IGP",
        "EGP",
        "INCOMPLETE"
    };

    if (pa->origin > 2) {
        return;
    }

    printf("origin=%s ", origin_string[ pa->origin ]);
}

void print_pa_as_path(struct bgp_path_attribute *pa) {
    struct path_segment *seg;
    struct list_head *i;

    if (!pa->as_path) {
        return;
    }

    printf(
        "n_as_segments=%d n_total_as=%d ", pa->as_path->n_segments, pa->as_path->n_total_as
    );

    printf("as_path=\"");
    list_for_each(i, &pa->as_path->segments) {
        seg = list_entry(i, struct path_segment, list);
        for (int x = 0; x < seg->n_as; x++) {
            printf("%d", seg->as[x]);
            //No comma on the last entry
            if (x == seg->n_as - 1) {
                break;
            }
            printf(",");
        }
    }
    printf("\" ");
}

//This is gross and yuck
void print_ipv4(uint32_t ipv4) {
    uint8_t octets[4];

    octets[0] = (uint8_t) ((ipv4 & 0xff000000) >> 24);
    octets[1] = (uint8_t) ((ipv4 & 0x00ff0000) >> 16);
    octets[2] = (uint8_t) ((ipv4 & 0x0000ff00) >> 8);
    octets[3] = (uint8_t) (ipv4 & 0x000000ff);

    printf("%d.%d.%d.%d",
        octets[3],
        octets[2],
        octets[1],
        octets[0]
    );
}

void print_next_hop(struct bgp_path_attribute *pa) {
    printf("next_hop=");
    print_ipv4(pa->next_hop);
    printf(" ");
}

void print_med(struct bgp_path_attribute *pa) {
    printf("med=%d ", pa->multi_exit_disc);
}

void print_local_pref(struct bgp_path_attribute *pa) {
    printf("local_pref=%d ", pa->local_pref);
}

void print_atomic_aggregate(struct bgp_path_attribute *pa) {
    printf("atomic_aggregate=1 ");
}

void print_aggregator(struct bgp_path_attribute *pa) {
    printf("aggregator_asn=%d ", pa->aggregator->asn);
    printf("aggregator_ip=");
    print_ipv4(pa->aggregator->ip);
    printf(" ");
}


void print_update(struct bgp_msg *msg) {
    struct list_head *i;
    struct ipv4_nlri *nlri;

    //+1 to account for 0 at the start
    void (*path_attr_dispatch[AGGREGATOR + 1]) (struct bgp_path_attribute *) = {
        NULL,
        &print_pa_origin,
        &print_pa_as_path,
        &print_next_hop,
        &print_med,
        &print_local_pref,
        &print_atomic_aggregate,
        &print_aggregator
    };


    //Print withdrawn routes
    printf(
        "widthdrawn_route_length=%d withdrawn_routes=\"",
        msg->update->withdrawn_route_length
    );

    list_for_each(i, &msg->update->withdrawn_routes) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        printf("%s", nlri->string);
        if (!list_is_last(i, &msg->update->withdrawn_routes)) {
            printf(",");
        }
    }
    printf("\" ");


    //Print path attributes
    printf(
        "path_attribute_length=%d ",
        msg->update->path_attr_length
    );
    for (int x = 0; x < AGGREGATOR; x++) {
        if (!msg->update->path_attrs[x] || !path_attr_dispatch[x]) {
            continue;
        }

        path_attr_dispatch[x](msg->update->path_attrs[x]);
    }

    //Print NLRI
    printf("nlri=\"");
    list_for_each(i, &msg->update->nlri) {
        nlri = list_entry(i, struct ipv4_nlri, list);
        printf("%s", nlri->string);
        if (!list_is_last(i, &msg->update->nlri)) {
            printf(",");
        }
    }
    printf("\"\n");
}


void print_notification(struct bgp_msg *msg) {
    printf(
        "code=%d, subcode=%d, data=\n",
        msg->notification.code,
        msg->notification.subcode
    );

}

void print_keepalive(struct bgp_msg *msg) {
    printf("\n");
}

void print_routerefresh(struct bgp_msg *msg) {

}
