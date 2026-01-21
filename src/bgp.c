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
#include "bgp_capability.h"
#include "bgp_timers.h"

#include "debug.h"
#include "log.h"
#include "tcp_client.h"
#include "byte_conv.h"
#include "output_queue.h"


struct bgp_instance {
    uint8_t version;
    uint16_t local_asn;
    uint32_t local_rid;
    int n_peers;
    struct bgp_peer *peers[MAX_BGP_PEERS];
    struct output_queue *output_queue;
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

// Wrapper functions for queuing and sending messages
ssize_t queue_and_send_open(struct bgp_peer *peer, uint8_t version, uint16_t asn,
                            uint16_t hold_time, uint32_t router_id,
                            struct bgp_capabilities *caps);
ssize_t queue_and_send_keepalive(struct bgp_peer *peer);
ssize_t queue_and_send_notification(struct bgp_peer *peer, uint8_t code, uint8_t subcode);

// Returns 1 if hold timer expired (and handles notification/cleanup), 0 otherwise
int check_hold_timer_expired(struct bgp_peer *peer, fd_set *set, const char *state_name);

//End Non-public functions

/*
    ================================

    Reconnection Helper Functions

    ================================
*/

/*
 * classify_failure() - Determine if a failure is retriable
 *
 * Returns 1 if the failure is retriable, 0 if non-retriable.
 *
 * Retriable failures:
 *   - TCP connection failure (code=0)
 *   - Hold timer expired
 *   - CEASE/Admin Shutdown
 *   - CEASE/Admin Reset
 *   - CEASE/Connection Rejected
 *
 * Non-retriable failures (typically config errors):
 *   - Version mismatch (OPEN error)
 *   - Bad peer AS (OPEN error)
 *   - Unacceptable hold time
 *   - Peer de-configured
 */
int classify_failure(uint8_t code, uint8_t subcode) {
    // TCP failure (no NOTIFICATION received)
    if (code == 0) {
        return 1;
    }

    // Hold timer expired - retriable
    if (code == BGP_ERR_HOLD_TIMER) {
        return 1;
    }

    // FSM error - retriable
    if (code == BGP_ERR_FSM) {
        return 1;
    }

    // CEASE errors - check subcode
    if (code == BGP_ERR_CEASE) {
        switch (subcode) {
            case BGP_ERR_CEASE_ADMIN_SHUT:   // Administrative Shutdown
            case BGP_ERR_CEASE_ADMIN_RESET:  // Administrative Reset
            case BGP_ERR_CEASE_CONN_REJECT:  // Connection Rejected
            case BGP_ERR_CEASE_CONFIG_CHG:   // Other Configuration Change
            case BGP_ERR_CEASE_COLLISION:    // Connection Collision
            case BGP_ERR_CEASE_RESOURCES:    // Out of Resources
                return 1;
            case BGP_ERR_CEASE_PEER_DECONF:  // Peer De-configured - non-retriable
            case BGP_ERR_CEASE_MAX_PREFIX:   // Max prefixes - non-retriable
            default:
                return 0;
        }
    }

    // OPEN errors - typically configuration problems, non-retriable
    if (code == BGP_ERR_OPEN) {
        return 0;
    }

    // Header and UPDATE errors - non-retriable (protocol problems)
    return 0;
}

/*
 * calculate_next_backoff() - Double the current backoff up to max
 */
void calculate_next_backoff(struct bgp_peer *peer) {
    uint16_t next = peer->reconnect_backoff_current * 2;
    if (next > peer->reconnect_backoff_max) {
        next = peer->reconnect_backoff_max;
    }
    peer->reconnect_backoff_current = next;
}

/*
 * reset_backoff() - Reset backoff to initial value (5s)
 */
void reset_backoff(struct bgp_peer *peer) {
    peer->reconnect_backoff_current = 5;
}

/*
 * setup_reconnect_timer() - Arm IdleHoldTimer with current backoff value
 */
int setup_reconnect_timer(struct bgp_peer *peer) {
    peer->local_timers[IdleHoldTimer].timeout.it_value.tv_sec = peer->reconnect_backoff_current;
    peer->local_timers[IdleHoldTimer].timeout.it_value.tv_nsec = 0;
    peer->local_timers[IdleHoldTimer].timeout.it_interval.tv_sec = 0;
    peer->local_timers[IdleHoldTimer].timeout.it_interval.tv_nsec = 0;
    return start_timer(peer->local_timers, IdleHoldTimer);
}


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

    /* Initialize output queue */
    i->output_queue = malloc(sizeof(*i->output_queue));
    if (!i->output_queue) {
        log_print(LOG_ERROR, "Failed to allocate output queue\n");
        free(i);
        return NULL;
    }

    if (output_queue_init(i->output_queue) < 0) {
        free(i->output_queue);
        free(i);
        return NULL;
    }

    if (output_queue_start(i->output_queue) < 0) {
        output_queue_destroy(i->output_queue);
        free(i->output_queue);
        free(i);
        return NULL;
    }

    return i;
}

void free_bgp_instance(struct bgp_instance *i) {
    if (i->output_queue) {
        output_queue_shutdown(i->output_queue);
        output_queue_join(i->output_queue);
        output_queue_destroy(i->output_queue);
        free(i->output_queue);
    }
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

    //Initialise reconnection settings
    peer->reconnect_enabled = 0;
    peer->reconnect_max_retries = 0;
    peer->reconnect_backoff_current = 5;
    peer->reconnect_backoff_max = 120;
    peer->last_notification_code = 0;
    peer->last_notification_subcode = 0;

    //Initialise al statistics to 0
    memset(&peer->stats, 0, sizeof(peer->stats));

    //Create the local timer FDs and initialise the default values
    if (initialise_local_timers(peer->local_timers) < 0) {
        return -1;
    }

    //Set an invalid socket
    peer->socket.fd = -1;

    peer->peer_asn = peer_asn;

    //Init the stdout lock and the output function
    pthread_mutex_init(&peer->stdout_lock, NULL);
    initialise_output(peer);

    //Set output queue from instance
    peer->output_queue = i->output_queue;

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



int set_bgp_output(struct bgp_instance *i, unsigned int id,  enum bgp_output format) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return -1;
    }

    return    _set_bgp_output(peer, format);
}

int set_bgp_reconnect(struct bgp_instance *i, unsigned int id, int enabled, int max_retries) {
    struct bgp_peer *peer;

    if (!(peer = get_peer_from_instance(i, id))) {
        return -1;
    }

    peer->reconnect_enabled = enabled;
    peer->reconnect_max_retries = max_retries;

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






/*
 * check_hold_timer_expired() - Check if hold timer fired and handle it
 *
 * Returns 1 if timer expired (sends NOTIFICATION, closes socket, sets IDLE)
 * Returns 0 if timer has not expired
 */
int check_hold_timer_expired(struct bgp_peer *peer, fd_set *set, const char *state_name) {
    if (!timer_has_fired(peer->local_timers, HoldTimer, set)) {
        return 0;
    }

    log_print(LOG_WARN, "HoldTimer expired in %s for peer %s\n", state_name, peer->name);
    queue_and_send_notification(peer, BGP_ERR_HOLD_TIMER, 0);
    bgp_close_socket(peer);
    peer->fsm_state = IDLE;
    peer->last_notification_code = BGP_ERR_HOLD_TIMER;
    peer->last_notification_subcode = 0;
    return 1;
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


void print_bgp_msg_and_gc(struct bgp_peer *peer) {
    struct bgp_msg *msg = NULL;
    struct list_head *i, *tmp;
    char *json_str;

    if (list_empty(&peer->output_q)) {
        return;
    }

    list_for_each_safe(i, tmp, &peer->output_q) {
        msg = list_entry(i, struct bgp_msg, output);
        //Don't print if the message hasn't been actioned yet
        if (!msg->actioned) {
            break;
        }

        /* Format the message based on output format */
        if (peer->output_format == BGP_OUT_JSONL) {
            json_str = format_msg_jsonl(msg);
        } else {
            json_str = format_msg_json(msg);
        }

        /* Push to output queue (queue takes ownership of json_str) */
        if (json_str && peer->output_queue) {
            output_queue_push(peer->output_queue, json_str);
        } else if (json_str) {
            /* Fallback: direct print if no queue (shouldn't happen) */
            printf("%s\n", json_str);
            free(json_str);
        }

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
    int max_fd, readable_fds, ret = 0;
    struct timeval select_timeout;
    int waiting_for_reconnect = 0;
    int was_established = 0;  // Track if we ever reached ESTABLISHED

    log_print(LOG_DEBUG, "RW Thread Active\n");

    set = calloc(1, sizeof(*set));

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

        // Check if IdleHoldTimer fired (reconnection timer)
        if (waiting_for_reconnect) {
            if (timer_has_fired(peer->local_timers, IdleHoldTimer, set)) {
                log_print(LOG_INFO, "Reconnect timer fired, attempting reconnection to %s\n", peer->name);
                waiting_for_reconnect = 0;
                peer->fsm_state = IDLE;
                // Calculate next backoff for potential future retry
                calculate_next_backoff(peer);
            }
            continue;
        }

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
            if (peer->socket.fd >= 0 && FD_ISSET(peer->socket.fd, set)) {
                log_print(LOG_DEBUG, "Calling recv_msg() on socket\n");
                message = recv_msg(peer->socket.fd);

                if (!message) {
                    log_print(LOG_ERROR, "recv_msg() errored\n");
                    bgp_close_socket(peer);
                    peer->fsm_state = IDLE;
                    peer->last_notification_code = 0;
                    peer->last_notification_subcode = 0;
                    goto handle_failure;
                }

                //Update peer-related fields
                message->peer_name = peer->name;
                message->id = peer->stats.total++;

                log_print(LOG_DEBUG, "Adding to ingress and output queues\n");
                list_add_tail(&message->ingress, &peer->ingress_q);
                list_add_tail(&message->output, &peer->output_q);
            }
        } else if (readable_fds < 0) {
            log_print(LOG_ERROR, "select() error\n");
            peer->last_notification_code = 0;
            peer->last_notification_subcode = 0;
            goto handle_failure;
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
            goto handle_failure;
        }

        // Reset backoff when we reach ESTABLISHED state
        if (peer->fsm_state == ESTABLISHED && !was_established) {
            was_established = 1;
            if (peer->connect_retry_counter > 0) {
                log_print(LOG_INFO, "Session established with %s, resetting backoff\n", peer->name);
                reset_backoff(peer);
                peer->connect_retry_counter = 0;
            }
        } else if (peer->fsm_state != ESTABLISHED) {
            was_established = 0;
        }

        //Output and garbage collect the messages
        //TODO: The garbage collection and the printing need to be decoupled. There's an issue
        //if the socket is RST before actioning, then the message doesn't get printed.
        print_bgp_msg_and_gc(peer);
        continue;

    handle_failure:
        // Print any pending messages before handling failure
        print_bgp_msg_and_gc(peer);

        // Check if reconnection is enabled and failure is retriable
        if (peer->reconnect_enabled) {
            int retriable = classify_failure(peer->last_notification_code, peer->last_notification_subcode);

            if (retriable) {
                // Check max retries
                if (peer->reconnect_max_retries == 0 ||
                    peer->connect_retry_counter < (unsigned int)peer->reconnect_max_retries) {

                    peer->connect_retry_counter++;
                    log_print(LOG_INFO, "Reconnecting to %s in %ds (attempt %d%s)\n",
                        peer->name,
                        peer->reconnect_backoff_current,
                        peer->connect_retry_counter,
                        peer->reconnect_max_retries > 0 ? "" : ", unlimited");

                    setup_reconnect_timer(peer);
                    waiting_for_reconnect = 1;
                    was_established = 0;
                    continue;
                } else {
                    log_print(LOG_ERROR, "Max retries (%d) reached for peer %s, giving up\n",
                        peer->reconnect_max_retries, peer->name);
                    goto exit_thread;
                }
            } else {
                log_print(LOG_ERROR, "Non-retriable failure (code=%d, subcode=%d) for peer %s\n",
                    peer->last_notification_code, peer->last_notification_subcode, peer->name);
                goto exit_thread;
            }
        } else {
            // Reconnection disabled, exit
            goto exit_thread;
        }
    }

    //Graceful shutdown: send CEASE notification if socket is still open
    if (peer->socket.fd >= 0) {
        log_print(LOG_INFO, "Sending graceful shutdown to peer %s\n", peer->name);
        queue_and_send_notification(peer, BGP_ERR_CEASE, BGP_ERR_CEASE_ADMIN_SHUT);
        print_bgp_msg_and_gc(peer);  // Print the notification before closing
        bgp_close_socket(peer);
    }

exit_thread:
    // Disarm reconnect timer if waiting
    if (waiting_for_reconnect) {
        disarm_timer(peer->local_timers, IdleHoldTimer);
    }

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
        // TCP failure - no NOTIFICATION
        peer->last_notification_code = 0;
        peer->last_notification_subcode = 0;
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
    struct bgp_capabilities *caps;

    log_print(LOG_DEBUG, "Peer %s FSM state: CONNECT\n", peer->name);

    /* Build capabilities to advertise */
    caps = bgp_capabilities_create();
    if (caps) {
        bgp_capabilities_add_route_refresh(caps);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV4, BGP_SAFI_UNICAST);
        bgp_capabilities_add_mp_ext(caps, BGP_AFI_IPV6, BGP_SAFI_UNICAST);
    }

    //TODO: fix hold timer
    log_print(LOG_DEBUG, "Sending OPEN to peer %s\n", peer->name);
    /* Note: caps ownership transfers to the queued message, freed by free_msg() */
    queue_and_send_open(peer, *peer->version, *peer->local_asn, 30, *peer->local_rid, caps);

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

    //Pop a message off the ingress queue - process messages before checking timers
    message = pop_ingress_queue(peer);

    //Did we receive a message, and was it an OPEN message?
    if (message) {
        if (message->type == OPEN) {
            log_print(LOG_DEBUG, "Checking OPEN for correctness\n");

            //Check peer ASN matches configured ASN
            if (message->open.asn != peer->peer_asn) {
                log_print(LOG_WARN, "Peer %s ASN mismatch: expected %d, got %d\n",
                    peer->name, peer->peer_asn, message->open.asn);
                queue_and_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPEN_PEER_AS);
                bgp_close_socket(peer);
                peer->fsm_state = IDLE;
                peer->last_notification_code = BGP_ERR_OPEN;
                peer->last_notification_subcode = BGP_ERR_OPEN_PEER_AS;
                return -1;
            }

            //Check BGP version
            if (message->open.version != *peer->version) {
                log_print(LOG_WARN, "Peer %s version mismatch: expected %d, got %d\n",
                    peer->name, *peer->version, message->open.version);
                queue_and_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPEN_VERSION);
                bgp_close_socket(peer);
                peer->fsm_state = IDLE;
                peer->last_notification_code = BGP_ERR_OPEN;
                peer->last_notification_subcode = BGP_ERR_OPEN_VERSION;
                return -1;
            }

            //Check hold time is acceptable (0 or >= 3 seconds per RFC 4271)
            if (message->open.hold_time != 0 && message->open.hold_time < 3) {
                log_print(LOG_WARN, "Peer %s unacceptable hold time: %d\n",
                    peer->name, message->open.hold_time);
                queue_and_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPEN_HOLD_TIME);
                bgp_close_socket(peer);
                peer->fsm_state = IDLE;
                peer->last_notification_code = BGP_ERR_OPEN;
                peer->last_notification_subcode = BGP_ERR_OPEN_HOLD_TIME;
                return -1;
            }

            //Store peer's router ID
            peer->peer_rid = message->open.router_id;

            // Negotiate hold time: use minimum of local and peer's, 0 if either is 0
            peer->peer_timers.recv_hold_time = message->open.hold_time;
            uint16_t negotiated_hold;
            if (peer->peer_timers.conf_hold_time == 0 || message->open.hold_time == 0) {
                negotiated_hold = 0;
            } else if (message->open.hold_time < peer->peer_timers.conf_hold_time) {
                negotiated_hold = message->open.hold_time;
            } else {
                negotiated_hold = peer->peer_timers.conf_hold_time;
            }

            log_print(LOG_INFO, "Peer %s hold time negotiated: %d (local=%d, peer=%d)\n",
                peer->name, negotiated_hold,
                peer->peer_timers.conf_hold_time, message->open.hold_time);

            // Update timer values based on negotiated hold time
            if (negotiated_hold > 0) {
                set_timer_value(peer->local_timers, HoldTimer, negotiated_hold);
                set_timer_value(peer->local_timers, KeepaliveTimer, negotiated_hold / 3);
            }

            //Sending a keepalive
            log_print(LOG_DEBUG, "Sending keepalive\n");
            queue_and_send_keepalive(peer);
            if (negotiated_hold > 0) {
                start_timer_recurring(peer->local_timers, KeepaliveTimer);
            }
            peer->fsm_state = OPENCONFIRM;
            return 0;
        } else if (message->type == NOTIFICATION) {
            log_print(LOG_WARN, "Received NOTIFICATION from peer %s in OPENSENT: code=%d, subcode=%d\n",
                peer->name, message->notification.code, message->notification.subcode);
            bgp_close_socket(peer);
            peer->fsm_state = IDLE;
            peer->last_notification_code = message->notification.code;
            peer->last_notification_subcode = message->notification.subcode;
            return -1;
        }
    }

    // Check hold timer AFTER processing messages
    if (check_hold_timer_expired(peer, set, "OPENSENT")) {
        peer->connect_retry_counter++;
        disarm_timer(peer->local_timers, ConnectRetryTimer);
        return -1;
    }

    return 0;
}

int fsm_state_openconfirm(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message;
    log_print(LOG_DEBUG, "Peer %s FSM state: OPENCONFIRM\n", peer->name);

    //If the Keepalive timer has fired, send a keepalive
    if ( timer_has_fired(peer->local_timers, KeepaliveTimer, set) ) {
        log_print(LOG_DEBUG, "Keepalive timer fired in OPENCONFIRM, sending KEEPALIVE\n");
        queue_and_send_keepalive(peer);
    }

    // Process incoming messages BEFORE checking hold timer
    message = pop_ingress_queue(peer);

    if (message) {
        if (message->type == KEEPALIVE) {
            log_print(LOG_INFO, "Received KEEPALIVE in OPENCONFIRM from peer %s, moving to ESTABLISHED\n", peer->name);
            start_timer(peer->local_timers, HoldTimer);
            peer->fsm_state = ESTABLISHED;
        } else if (message->type == NOTIFICATION) {
            log_print(LOG_WARN, "Received NOTIFICATION from peer %s in OPENCONFIRM: code=%d, subcode=%d\n",
                peer->name, message->notification.code, message->notification.subcode);
            bgp_close_socket(peer);
            peer->fsm_state = IDLE;
            peer->last_notification_code = message->notification.code;
            peer->last_notification_subcode = message->notification.subcode;
            return -1;
        }
    }

    // Check hold timer AFTER processing messages
    if (check_hold_timer_expired(peer, set, "OPENCONFIRM")) {
        return -1;
    }

    return 0;
}

int fsm_state_established(struct bgp_peer *peer, struct bgp_msg *msg, fd_set *set) {
    struct bgp_msg *message;
    log_print(LOG_DEBUG, "Peer %s FSM state: ESTABLISHED\n", peer->name);

    //If the Keepalive timer has fired, send a keepalive
    if ( timer_has_fired(peer->local_timers, KeepaliveTimer, set) ) {
        log_print(LOG_DEBUG, "Keepalive timer fired, sending KEEPALIVE\n");
        queue_and_send_keepalive(peer);
    }

    // Process incoming messages BEFORE checking hold timer.
    // This avoids a race where a KEEPALIVE arrives just as the timer fires.
    message = pop_ingress_queue(peer);

    if (message) {
        switch (message->type) {
            case KEEPALIVE:
                log_print(LOG_DEBUG, "Received KEEPALIVE, resetting HoldTimer\n");
                start_timer(peer->local_timers, HoldTimer);
                break;
            case NOTIFICATION:
                log_print(LOG_WARN, "Received NOTIFICATION from peer %s: code=%d, subcode=%d\n",
                    peer->name, message->notification.code, message->notification.subcode);
                bgp_close_socket(peer);
                peer->fsm_state = IDLE;
                peer->last_notification_code = message->notification.code;
                peer->last_notification_subcode = message->notification.subcode;
                return -1;
            case UPDATE:
                //UPDATE messages are printed but don't require specific FSM action
                log_print(LOG_DEBUG, "Received UPDATE from peer %s\n", peer->name);
                start_timer(peer->local_timers, HoldTimer);
                break;
        }
    }

    // Check hold timer AFTER processing messages - a just-arrived KEEPALIVE/UPDATE
    // will have reset it above, avoiding a false expiry
    if (check_hold_timer_expired(peer, set, "ESTABLISHED")) {
        return -1;
    }

    return 0;
}

/*
    Wrapper functions for queuing and sending messages
*/

ssize_t queue_and_send_open(struct bgp_peer *peer, uint8_t version, uint16_t asn,
                            uint16_t hold_time, uint32_t router_id,
                            struct bgp_capabilities *caps) {
    struct bgp_msg *msg = alloc_sent_msg();

    if (msg) {
        msg->id = -(++peer->stats.sent_total);
        msg->peer_name = peer->name;
        msg->type = OPEN;
        msg->length = 29;  // BGP header (19) + OPEN minimum (10)
        msg->open.version = version;
        msg->open.asn = asn;
        msg->open.hold_time = hold_time;
        msg->open.router_id = router_id;
        /* Store capabilities - takes ownership, will be freed by free_msg() */
        msg->open.capabilities = caps;
        msg->open.opt_param_len = caps ? (uint8_t)(caps->total_length + 2) : 0;
        list_add_tail(&msg->output, &peer->output_q);
    }

    return send_open(peer->socket.fd, version, asn, hold_time, router_id, caps);
}

ssize_t queue_and_send_keepalive(struct bgp_peer *peer) {
    struct bgp_msg *msg = alloc_sent_msg();

    if (msg) {
        msg->id = -(++peer->stats.sent_total);
        msg->peer_name = peer->name;
        msg->type = KEEPALIVE;
        msg->length = 19;  // BGP header only
        list_add_tail(&msg->output, &peer->output_q);
    }

    return send_keepalive(peer->socket.fd);
}

ssize_t queue_and_send_notification(struct bgp_peer *peer, uint8_t code, uint8_t subcode) {
    struct bgp_msg *msg = alloc_sent_msg();

    if (msg) {
        msg->id = -(++peer->stats.sent_total);
        msg->peer_name = peer->name;
        msg->type = NOTIFICATION;
        msg->length = 21;  // BGP header (19) + code (1) + subcode (1)
        msg->notification.code = code;
        msg->notification.subcode = subcode;
        msg->notification.data = NULL;
        list_add_tail(&msg->output, &peer->output_q);
    }

    return send_notification(peer->socket.fd, code, subcode);
}

