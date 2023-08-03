#include <string.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <stdint.h> 
#include <unistd.h> 
#include <errno.h> 
#include <math.h>

#include <pthread.h>

 
#define TCP_BGP_PORT 179 
 
#include "bgp.h"
#include "bgp_peer.h"
#include "bgp_message.h"
#include "bgp_print.h"
#include "bgp_timers.h"

#include "debug.h"
#include "tcp_client.h"
#include "byte_conv.h"


struct bgp_instance {
    uint8_t version;
    uint16_t local_asn;
    uint32_t local_rid;
    int n_peers;
    struct bgp_peer *peers[MAX_BGP_PEERS];
};

//Start Non-public functions:

void *bgp_peer_thread(void *);

//FSM functions
int fsm_state_idle(struct bgp_peer *, fd_set *);
int fsm_state_connect(struct bgp_peer *);
int fsm_state_active(struct bgp_peer *);
int fsm_state_opensent(struct bgp_peer *, struct bgp_msg *, fd_set *);
int fsm_state_openconfirm(struct bgp_peer *, struct bgp_msg *, fd_set *);
int fsm_state_established(struct bgp_peer *, struct bgp_msg *, fd_set *);

struct bgp_msg *create_bgp_open(struct bgp_peer *peer);

//End Non-public functions


/*
    BGP Instance and peer creation/destruction functions
*/


struct bgp_instance *create_bgp_instance(uint16_t local_asn, uint32_t local_rid, uint8_t version) {
    struct bgp_instance *i;

    DEBUG_PRINT("Created new peer (ASN %d, RID: %d, Version: %d)\n", local_asn, local_rid, version);

    i = calloc(1, sizeof(*i));

    if (!i) {
        return NULL;
    }

    i->version = version;
    i->local_asn = local_asn;
    i->local_rid = local_rid;
    i->n_peers = 0;

    return i;
}

void free_bgp_instance(struct bgp_instance *i) {
    free(i);
}

unsigned int max_peer_id(struct bgp_instance *i) {
    return ( sizeof(i->peers) / sizeof(*(i->peers)) ) - 1;
}

//Peer ID checks in the BGP instance
int valid_peer_id(struct bgp_instance *i, unsigned int id) {
    unsigned int max_id = max_peer_id(i);
    if (id > max_id) { return 0; }

    //Ensure the peer is actually allocated
    if (i->peers[id] == NULL) {
        return 0;
    }

    return 1;
}

struct bgp_peer *get_peer_from_instance(struct bgp_instance *i, unsigned int id) {
    if (!valid_peer_id(i, id)) {
        return NULL;
    }

    return i->peers[id];
}


//TODO: Need to fix unsigned here, as we need to be able to signal failure of the function
unsigned int create_bgp_peer(struct bgp_instance *i, const char *peer_ip, const uint16_t peer_asn, const char *peer_name) {
    struct bgp_peer *peer;
    unsigned int new_id;

    //Find a slot in the BGP instance
    for(new_id = 0; new_id < max_peer_id(i); new_id++) {
        if (i->peers[new_id] != NULL) {
            DEBUG_PRINT("Slot %d taken\n", new_id);
            continue;
        }
        DEBUG_PRINT("Found slot %d available for peer %s (%s)\n", new_id, peer_name, peer_ip);
        break;
    }

    peer = malloc(sizeof(*peer));

    if (peer == NULL) {
        DEBUG_PRINT("Unable to malloc() memory for peer %s\n", peer_name);
        return -1;
    }

    //Add the new peer to the instance
    i->peers[new_id] = peer;
    i->n_peers++;

    peer->fsm_state = IDLE;
    //Copy the attributes into our structure
    //TODO: check malloc return values
    peer->peer_ip = malloc((strlen(peer_ip) + 1) * sizeof(*peer_ip));
    peer->name = malloc((strlen(peer_name) + 1) * sizeof(*peer_name));
    strncpy(peer->peer_ip, peer_ip, strlen(peer_ip) + 1);
    strncpy(peer->name, peer_name, strlen(peer_name) + 1);

    //Some values are global from the BGP instance
    peer->version = &i->version;
    peer->local_asn = &i->local_asn;
    peer->local_rid = &i->local_rid;

    //Set up the hold time
    #define HOLD_TIME 30
    peer->peer_timers.conf_hold_time = HOLD_TIME;
    peer->peer_timers.recv_hold_time = 0;
    peer->peer_timers.curr_hold_time = &peer->peer_timers.conf_hold_time;

    //Initialise the connect rety counter
    peer->connect_retry_counter = 0;

    //Initialise al statistics to 0
    memset(&peer->stats, 0, sizeof(peer->stats));

    //Create the local timer FDs and initialise the default values
    if (initialise_local_timers(peer->local_timers) < 0) {
        return -1;
    }

    //Set an invalid socket
    peer->socket.fd = -1;

    peer->peer_asn = peer_asn;

    //Init the stdout lock
    initialise_output(peer);

    //Init message queue
    INIT_LIST_HEAD(&peer->ingress_q);
    INIT_LIST_HEAD(&peer->output_q);

    return new_id;
}

void free_bgp_peer(struct bgp_instance *i, unsigned int id) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return;
    }

    //Free the malloc'ed attributes, free the peer and reset the slot
    free(peer->peer_ip);
    free(peer->name);

    pthread_mutex_destroy(&peer->stdout_lock);

    free(peer);
    i->n_peers--;
    i->peers[id] = NULL;
}

void free_all_bgp_peers(struct bgp_instance *i) {
    for (unsigned int id = 0; id < max_peer_id(i); id++) {
        free_bgp_peer(i, id);
    }
}


int activate_bgp_peer(struct bgp_instance *i, unsigned int id) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return -1;
    }

    peer->active = 1;

    if (pthread_create(&peer->thread, NULL, bgp_peer_thread, peer) != 0) {
        DEBUG_PRINT("Unable to create peer thread\n");
        return -1;
    }

    return 0;
}

int deactivate_bgp_peer(struct bgp_instance *i, unsigned int id) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return -1;
    }

    peer->active = 0;

    DEBUG_PRINT("Waiting for peer ID %d to exit\n", id);
    pthread_join(peer->thread, NULL);

    return 0;
}

int deactivate_all_bgp_peers(struct bgp_instance *i) {
    int ret = 0;

    //Valid ID checking occurs in deactivate_bgp_peer()
    for (unsigned int id = 0; id < max_peer_id(i); id++) {
        if ( !deactivate_bgp_peer(i, id) ) {
            ret--;
        }
    }

    return ret;
}


void bgp_close_socket(struct bgp_peer *peer) {
    close(peer->socket.fd);
    peer->socket.fd = -1;
    peer->fsm_state = IDLE;
}
   

/*
    ================================ 

    Peer Finite State Machine Functions

    ================================
*/

struct peer_fd_set {
    int n_fds;
    fd_set fds;
};

int get_read_fd_set(struct bgp_peer *peer, fd_set *set) {
    int max_fd = 0;
    int temp_fd = 0;
    //Set up the select() set  

    FD_ZERO(set);

    //Add all of the timer FDs, and keep track of the max
    for (int timer_id = 0; timer_id < N_LOCAL_TIMERS; timer_id++) {
        temp_fd = peer->local_timers[timer_id].fd;
        FD_SET(temp_fd, set);
        max_fd = (temp_fd > max_fd) ? temp_fd : max_fd;
    }

    //Add our socket FD (which may not be valid yet)
    if (peer->socket.fd > 0) {
        FD_SET(peer->socket.fd, set);   
        max_fd = (peer->socket.fd > max_fd) ? peer->socket.fd : max_fd;
    }
    
    //Return the max file descriptor
    return max_fd;
}


/*
 bgp_peer_thread() - thread entry point for each activarted BGP thread
*/

void *bgp_peer_thread(void *param) {
    struct bgp_peer *peer = param;
    struct bgp_msg *message = NULL;
    fd_set *set;
    int max_fd, readable_fds;
    struct timeval select_timeout;

    DEBUG_PRINT("RW Thread Active\n");

    set = malloc(sizeof(*set));

    if (!set) {
        DEBUG_PRINT("Unable to allocate space for FD_SET\n");
        return NULL;
    }

    while(peer->active) {
        //Reset select timer
        select_timeout = (struct timeval){ .tv_sec = 1, .tv_usec = 0 };
        max_fd = get_read_fd_set(peer, set);
        //TODO: handle signals
        readable_fds = select(max_fd + 1, set, NULL, NULL, &select_timeout);
        /*
            Did we have a timer fire, did we receive a message, or did the underlying TCP
            stream fail (FIN or RST)? We gather this information and pass it to each of 
            the state functions.

            Currently we only receive the first timer that fired. A TODO is to multiplex
            this into a bitfield for multiple timers.
        */
        if (readable_fds > 0) {
            DEBUG_PRINT("select() is readable (FD %d)\n", readable_fds);

            //Did we receive messages?
            if (FD_ISSET(peer->socket.fd, set)) {
                DEBUG_PRINT("Calling recv_msg() on socket\n");
                message = recv_msg(peer->socket.fd);

                if (!message) {
                    DEBUG_PRINT("recv_msg() errored, exiting\n");
                    bgp_close_socket(peer);
                    peer->fsm_state = IDLE;
                    goto error;
                }

                //Update peer-related fields
                message->peer_name = peer->name;
                message->id = peer->stats.total++;

                DEBUG_PRINT("Adding to ingress and output queues\n");
                list_add_tail(&message->ingress, &peer->ingress_q);
                list_add_tail(&message->output, &peer->output_q);
            }
        } else if (readable_fds < 0) {
            DEBUG_PRINT("select() error, peer thread returning\n");
            return NULL;
        }

        /* 
            Each FSM is passed the results from select(), and bears its own responsibility
            for reading in socket data, or dealing with timers that may have expired
        */
        switch(peer->fsm_state) {
            case IDLE: 
                fsm_state_idle(peer, set);
                break;
            case CONNECT: 
                fsm_state_connect(peer);
                break;
            case ACTIVE: 
                fsm_state_active(peer);
                break;
            case OPENSENT: 
                fsm_state_opensent(peer, message, set);
                break;
            case OPENCONFIRM:
                fsm_state_openconfirm(peer, message, set);
                break;
            case ESTABLISHED:
                fsm_state_established(peer, message, set);
                break;
            default:
                DEBUG_PRINT("Invalid FSM state for peer %s: %d\n", peer->name, peer->fsm_state);
        }

        //Output and garbage collect the messages
        print_bgp_msg_and_gc(peer);
    }

    error:
    free(set);

    return NULL;
}

//TODO: Whole bunch of timer relates stuff needs to go in here.


struct bgp_msg *pop_ingress_queue(struct bgp_peer *peer) {
    struct bgp_msg *msg;

    if (!list_empty(&peer->ingress_q)) {
        msg = list_first_entry(&peer->ingress_q, struct bgp_msg, ingress);
        list_del(&msg->ingress);
        msg->actioned = 1;
        return msg;
    }

    return NULL;
}

int fsm_state_idle(struct bgp_peer *peer, fd_set *set) {
    //Is the ConnectRetryTimer still running
    //if( !timer_has_fired(peer->local_timers, ConnectRetryTimer, set) ) {
    //    DEBUG_PRINT("ConnectRetryTimer running, no TCP initialisation\n");
    //    return 1;
    //}

    //Start the ConnectRetryTimer
    start_timer(peer->local_timers, ConnectRetryTimer);
    
    peer->socket.fd = tcp_connect(peer->peer_ip, "179");
    fprintf(stderr, " - Opening connection to %s,%d (%s)\n", peer->peer_ip, peer->peer_asn, peer->name);

    if (peer->socket.fd < 0) {
        DEBUG_PRINT("TCP connection to %s failed\n", peer->peer_ip);
        bgp_close_socket(peer);
        return -1;
        //Update timer
    }

    //TCP connection was successful
    DEBUG_PRINT("TCP connection to %s successful\n", peer->peer_ip);
    disarm_timer(peer->local_timers, ConnectRetryTimer);
    peer->fsm_state = CONNECT;

    return 0;
}

int fsm_state_connect(struct bgp_peer *peer) {
    DEBUG_PRINT("Peer %s FSM state: CONNECT\n", peer->name);

    //TODO: fix hold timer
    DEBUG_PRINT("Sending OPEN to peer %s\n", peer->name);
    send_open(peer->socket.fd, *peer->version, *peer->local_asn, 30, *peer->local_rid);

    start_timer(peer->local_timers, HoldTimer);
    peer->fsm_state = OPENSENT;

    return 0;
}

//We don't set up a listening socket at the moment, so we should never
//get to state ACTIVE
int fsm_state_active(struct bgp_peer *peer) {
    DEBUG_PRINT("Peer %s FSM state: ACTIVE\n", peer->name);
    return 0;
}

int fsm_state_opensent(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message = NULL;
    DEBUG_PRINT("Peer %s FSM state: OPENSENT\n", peer->name);

    //Did the hold timer expire?
    if( which_timer_fired(peer->local_timers, set) == HoldTimer ) {
        DEBUG_PRINT("Our HoldTimer fired in OPENSENT. Closing connection and moving to IDLE\n");
        //TODO: Send a notifcation
        peer->connect_retry_counter++;
        disarm_timer(peer->local_timers, ConnectRetryTimer);
        bgp_close_socket(peer);
        peer->fsm_state = IDLE;
        return -1;
    }

    //Pop a message off the ingress queue
    message = pop_ingress_queue(peer);

    //Did we receive a message, and was it an OPEN message?
    //TODO: Need to free this message allocation somewhere
    if (message) {
        if (message->type == OPEN) {
            DEBUG_PRINT("Checking OPEN for correctness\n");
            //TODO: Check the peer's OPEN parameters are correct
            
            //Sending a keepalive
            DEBUG_PRINT("Sending keepalive\n");
            send_keepalive(peer->socket.fd);
            //TODO: confirm timers
            //TODO :HoldTimer needs to be negotiated value
            //start_local_timer(peer, HoldTimer);
            //Set the keepalive
            start_timer_recurring(peer->local_timers, KeepaliveTimer);
            peer->fsm_state = OPENCONFIRM;
            return 0;
        }
    }

    return 0;
}
int fsm_state_openconfirm(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message;

    message = pop_ingress_queue(peer); 

    if (message) {
        if (message->type == KEEPALIVE) {
            DEBUG_PRINT("Received keepalive in OPENCONFIRM, moving to ESTABLISHED\n");
            peer->fsm_state = ESTABLISHED;
        }
    }

    return 0;
}

int fsm_state_established(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message;

    //If the Keepalive timer has fired, send a keepalive
    if ( timer_has_fired(peer->local_timers, KeepaliveTimer, set) ) {
        DEBUG_PRINT("Keepalive timer fired, sending KEEPALIVE\n");
        send_keepalive(peer->socket.fd);
    }

    message = pop_ingress_queue(peer);

    if (message) {
        switch (message->type) {
            case KEEPALIVE:
                DEBUG_PRINT("Received KEEPALIVE, resetting HoldTimer\n");
                start_timer(peer->local_timers, HoldTimer);
                break;
        }
    }

    return 0;
}

