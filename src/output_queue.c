#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "output_queue.h"
#include "log.h"

int output_queue_init(struct output_queue *q) {
    INIT_LIST_HEAD(&q->items);
    q->shutdown = 0;

    if (pthread_mutex_init(&q->lock, NULL) != 0) {
        log_print(LOG_ERROR, "Failed to initialize output queue mutex\n");
        return -1;
    }

    if (pthread_cond_init(&q->cond, NULL) != 0) {
        log_print(LOG_ERROR, "Failed to initialize output queue condition variable\n");
        pthread_mutex_destroy(&q->lock);
        return -1;
    }

    return 0;
}

void output_queue_destroy(struct output_queue *q) {
    struct list_head *i, *tmp;
    struct output_item *item;

    /* Free any remaining items */
    list_for_each_safe(i, tmp, &q->items) {
        item = list_entry(i, struct output_item, list);
        list_del(i);
        free(item->json_str);
        free(item);
    }

    pthread_cond_destroy(&q->cond);
    pthread_mutex_destroy(&q->lock);
}

void output_queue_push(struct output_queue *q, char *json_str) {
    struct output_item *item;

    if (!json_str) {
        return;
    }

    item = malloc(sizeof(*item));
    if (!item) {
        log_print(LOG_ERROR, "Failed to allocate output queue item\n");
        free(json_str);
        return;
    }

    item->json_str = json_str;

    pthread_mutex_lock(&q->lock);
    list_add_tail(&item->list, &q->items);
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

void output_queue_shutdown(struct output_queue *q) {
    pthread_mutex_lock(&q->lock);
    q->shutdown = 1;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

int output_queue_start(struct output_queue *q) {
    if (pthread_create(&q->writer_thread, NULL, output_writer_thread, q) != 0) {
        log_print(LOG_ERROR, "Failed to create output writer thread\n");
        return -1;
    }
    return 0;
}

void output_queue_join(struct output_queue *q) {
    pthread_join(q->writer_thread, NULL);
}

void *output_writer_thread(void *arg) {
    struct output_queue *q = arg;
    struct output_item *item;
    struct list_head *first;

    log_print(LOG_DEBUG, "Output writer thread started\n");

    while (1) {
        pthread_mutex_lock(&q->lock);

        /* Wait for items or shutdown signal */
        while (list_empty(&q->items) && !q->shutdown) {
            pthread_cond_wait(&q->cond, &q->lock);
        }

        /* If shutdown and queue is empty, exit */
        if (q->shutdown && list_empty(&q->items)) {
            pthread_mutex_unlock(&q->lock);
            break;
        }

        /* Pop item from queue */
        first = q->items.next;
        item = list_entry(first, struct output_item, list);
        list_del(first);

        pthread_mutex_unlock(&q->lock);

        /* Write to stdout (this is where blocking is OK) */
        printf("%s\n", item->json_str);
        fflush(stdout);

        free(item->json_str);
        free(item);
    }

    log_print(LOG_DEBUG, "Output writer thread exiting\n");
    return NULL;
}
