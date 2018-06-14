/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "queue.h"

#include <assert.h>

/*
 * Single producer, single consumer queue, thread-safe.
 * Draining is handled externally by sending a sentinel down the queue.
 */

void
queue_init(queue_t *queue) {
	int rv;

	assert(queue);
	tommy_list_init(&queue->list);
	rv = pthread_mutex_init(&queue->mutex, NULL);
	assert(rv == 0);
	rv = pthread_cond_init(&queue->notempty, NULL);
	assert(rv == 0);
	queue->size = 0;
}

void
queue_destroy(queue_t *queue) {
	assert(queue);
	(void)pthread_cond_destroy(&queue->notempty);
	(void)pthread_mutex_destroy(&queue->mutex);
}

void
queue_enqueue(queue_t *queue, tommy_node *node, void *data) {
	assert(queue);
	assert(node);
	assert(data);

	pthread_mutex_lock(&queue->mutex);
	tommy_list_insert_tail(&queue->list, node, data);
	queue->size++;
	pthread_mutex_unlock(&queue->mutex);
	pthread_cond_signal(&queue->notempty);
}

void *
queue_dequeue(queue_t *queue) {
	void *data;

	assert(queue);
	pthread_mutex_lock(&queue->mutex);
	while (tommy_list_empty(&queue->list)) {
		pthread_cond_wait(&queue->notempty, &queue->mutex);
	}
	assert(!tommy_list_empty(&queue->list));
	assert(queue->size > 0);
	data = tommy_list_remove_existing(&queue->list,
	                                  tommy_list_head(&queue->list));
	queue->size--;
	pthread_mutex_unlock(&queue->mutex);
	assert(data);
	return data;
}

