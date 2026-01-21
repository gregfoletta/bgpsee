#pragma once

#include <pthread.h>
#include "list.h"

/*
 * Output Queue - Thread-safe queue for decoupling JSON formatting from stdout writes
 *
 * Problem: When stdout blocks (e.g., piped to slow consumer), peer threads stall
 * and can't send keepalives, causing remote hold timer to fire.
 *
 * Solution: Peer threads push formatted JSON strings to this queue (fast),
 * a dedicated writer thread pulls and writes to stdout (can block safely).
 */

struct output_item {
    char *json_str;          /* Formatted JSON string (owned by queue) */
    struct list_head list;   /* Queue link */
};

struct output_queue {
    struct list_head items;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int shutdown;            /* Signal writer thread to exit */
    pthread_t writer_thread;
};

/* Initialize the output queue (call before spawning writer thread) */
int output_queue_init(struct output_queue *q);

/* Destroy the output queue (call after writer thread has exited) */
void output_queue_destroy(struct output_queue *q);

/* Push a formatted JSON string to the queue (takes ownership of json_str) */
void output_queue_push(struct output_queue *q, char *json_str);

/* Signal the writer thread to shutdown and drain remaining items */
void output_queue_shutdown(struct output_queue *q);

/* Start the writer thread */
int output_queue_start(struct output_queue *q);

/* Wait for writer thread to finish */
void output_queue_join(struct output_queue *q);

/* Writer thread entry point */
void *output_writer_thread(void *arg);
