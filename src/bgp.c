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
#include "log.h"
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

    log_print(LOG_DEBUG, "Creating new peer (ASN %d, RID: %d, Version: %d)\n", local_asn, local_rid, version);

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
            log_print(LOG_DEBUG, "Slot %d taken\n", new_id);
            continue;
        }
        log_print(LOG_DEBUG, "Found slot %d available\n", new_id);
        break;
    }

    peer = malloc(sizeof(*peer));

    if (peer == NULL) {
        log_print(LOG_ERROR, "Unable to malloc() memory for peer %s\n", peer_name);
        return -1;
    }

    peer->id = new_id;

    //Add the new peer to the instance
    i->peers[new_id] = peer;
    i->n_peers++;

    peer->fsm_state = IDLE;
    //Copy the attributes into our structure

    //IP
    peer->peer_ip = sdsnew(peer_ip);
    peer->source_ip = sdsempty();

    strncpy(peer->peer_ip, peer_ip, strlen(peer_ip) + 1);

    peer->name = sdsnew(peer_name);

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


unsigned int bgp_peer_source(struct bgp_instance *i, unsigned int id, const char *src_ip) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        log_print(LOG_WARN, "Peer with ID %d does not exist for BGP instance\n");
        return -1;
    }

    //Has a source IP already been set?
    if (sdslen(peer->source_ip)) {
        log_print(LOG_WARN, "Source IP for peer %s already set to '%s', no change made\n", peer->name, peer->source_ip);
    }

    //Source IP is empty at this stage
    sdsfree(peer->source_ip);
    peer->source_ip = sdsnew(src_ip);

    return 0;
}



void free_bgp_peer(struct bgp_instance *i, unsigned int id) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return;
    }

    log_print(LOG_DEBUG, "Freeing peer ID %d (%s)\n", id, peer->name);

    //Free the malloc'ed attributes, free the peer and reset the slot
    sdsfree(peer->peer_ip);
    sdsfree(peer->source_ip);
    sdsfree(peer->name);

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
        log_print(LOG_DEBUG, "Unable to create peer thread\n");
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

    log_print(LOG_DEBUG, "Waiting for peer ID %d to exit\n", id);
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






void msg_queue_gc(struct list_head *queue) {
    struct bgp_msg *msg = NULL;
    struct list_head *i, *tmp;

    if (list_empty(queue)) {
        return;
    }

    list_for_each_safe(i, tmp, queue) {
        msg = list_entry(i, struct bgp_msg, output);
        list_del(i);
        free_msg(msg);
    }
}


/*
 bgp_peer_thread() - thread entry point for each activarted BGP thread
*/

void *bgp_peer_thread(void *param) {
    struct bgp_peer *peer = param;
    struct bgp_msg *message = NULL;
    fd_set *set;
    int max_fd, readable_fds, ret;
    struct timeval select_timeout;

    log_print(LOG_DEBUG, "RW Thread Active\n");

    set = calloc(sizeof(*set), 1);

    if (!set) {
        log_print(LOG_DEBUG, "Unable to allocate space for FD_SET\n");
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
            log_print(LOG_DEBUG, "select() is readable (FD %d)\n", readable_fds);

            //Did we receive messages?
            if (FD_ISSET(peer->socket.fd, set)) {
                log_print(LOG_DEBUG, "Calling recv_msg() on socket\n");
                message = recv_msg(peer->socket.fd);

                if (!message) {
                    log_print(LOG_ERROR, "recv_msg() errored, exiting\n");
                    bgp_close_socket(peer);
                    peer->fsm_state = IDLE;
                    goto error;
                }

                //Update peer-related fields
                message->peer_name = peer->name;
                message->id = peer->stats.total++;

                log_print(LOG_DEBUG, "Adding to ingress and output queues\n");
                list_add_tail(&message->ingress, &peer->ingress_q);
                list_add_tail(&message->output, &peer->output_q);
            }
        } else if (readable_fds < 0) {
            log_print(LOG_ERROR, "select() error, peer thread returning\n");
            goto error;
        }

        /* 
            Each FSM is passed the results from select(), and bears its own responsibility
            for reading in socket data, or dealing with timers that may have expired
        */
        switch(peer->fsm_state) {
            case IDLE: 
                ret = fsm_state_idle(peer, set);
                break;
            case CONNECT: 
                ret = fsm_state_connect(peer);
                break;
            case ACTIVE: 
                ret = fsm_state_active(peer);
                break;
            case OPENSENT: 
                ret = fsm_state_opensent(peer, message, set);
                break;
            case OPENCONFIRM:
                ret = fsm_state_openconfirm(peer, message, set);
                break;
            case ESTABLISHED:
                ret = fsm_state_established(peer, message, set);
                break;
            default:
                log_print(LOG_DEBUG, "Invalid FSM state for peer %s: %d\n", peer->name, peer->fsm_state);
        }

        if (ret < 0) {
            goto error;
        }

        //Output and garbage collect the messages
        //TODO: The garbage collection and the printing need to be decoupled. There's an issue
        //if the socket is RST before actioning, then the message doesn't get printed.
        print_bgp_msg_and_gc(peer);
    }

    error:
    free(set);
    msg_queue_gc(&peer->output_q);

    log_print(LOG_INFO, "Peer %s has closed\n", peer->name);

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
    //    log_print(LOG_DEBUG, "ConnectRetryTimer running, no TCP initialisation\n");
    //    return 1;
    //}

    //Start the ConnectRetryTimer
    start_timer(peer->local_timers, ConnectRetryTimer);
    
    log_print(LOG_INFO, "Opening connection to %s,%d (%s)\n", peer->peer_ip, peer->peer_asn, peer->name);
    peer->socket.fd = tcp_connect(peer->peer_ip, "179", peer->source_ip);

    if (peer->socket.fd < 0) {
        log_print(LOG_DEBUG, "TCP connection to %s failed\n", peer->peer_ip);
        bgp_close_socket(peer);
        return -1;
        //Update timer
    } else {
        log_print(LOG_INFO, "Connection to %s successful\n", peer->name);
    }

    //TCP connection was successful
    log_print(LOG_DEBUG, "TCP connection to %s successful\n", peer->peer_ip);
    disarm_timer(peer->local_timers, ConnectRetryTimer);
    peer->fsm_state = CONNECT;

    return 0;
}

int fsm_state_connect(struct bgp_peer *peer) {
    log_print(LOG_DEBUG, "Peer %s FSM state: CONNECT\n", peer->name);

    //TODO: fix hold timer
    log_print(LOG_DEBUG, "Sending OPEN to peer %s\n", peer->name);
    send_open(peer->socket.fd, *peer->version, *peer->local_asn, 30, *peer->local_rid);

    start_timer(peer->local_timers, HoldTimer);
    peer->fsm_state = OPENSENT;

    return 0;
}

//We don't set up a listening socket at the moment, so we should never
//get to state ACTIVE
int fsm_state_active(struct bgp_peer *peer) {
    log_print(LOG_DEBUG, "Peer %s FSM state: ACTIVE\n", peer->name);
    return 0;
}

int fsm_state_opensent(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message = NULL;
    log_print(LOG_DEBUG, "Peer %s FSM state: OPENSENT\n", peer->name);

    //Did the hold timer expire?
    if( which_timer_fired(peer->local_timers, set) == HoldTimer ) {
        log_print(LOG_DEBUG, "Our HoldTimer fired in OPENSENT. Closing connection and moving to IDLE\n");
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
            log_print(LOG_DEBUG, "Checking OPEN for correctness\n");
            //TODO: Check the peer's OPEN parameters are correct
            
            //Sending a keepalive
            log_print(LOG_DEBUG, "Sending keepalive\n");
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
            log_print(LOG_DEBUG, "Received keepalive in OPENCONFIRM, moving to ESTABLISHED\n");
            peer->fsm_state = ESTABLISHED;
        }
    }

    return 0;
}

int fsm_state_established(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message;

    //If the Keepalive timer has fired, send a keepalive
    if ( timer_has_fired(peer->local_timers, KeepaliveTimer, set) ) {
        log_print(LOG_DEBUG, "Keepalive timer fired, sending KEEPALIVE\n");
        send_keepalive(peer->socket.fd);
    }

    message = pop_ingress_queue(peer);

    if (message) {
        switch (message->type) {
            case KEEPALIVE:
                log_print(LOG_DEBUG, "Received KEEPALIVE, resetting HoldTimer\n");
                start_timer(peer->local_timers, HoldTimer);
                break;
        }
    }

    return 0;
}

