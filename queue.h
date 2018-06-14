/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef QUEUE_H
#define QUEUE_H

#include "attrib.h"

#include "tommylist.h"

#include <pthread.h>

typedef struct {
	tommy_list      list;
	pthread_mutex_t mutex;
	pthread_cond_t  notempty;
	size_t          size;
} queue_t;

void queue_init(queue_t *) NONNULL(1);
void queue_destroy(queue_t *) NONNULL(1);
void queue_enqueue(queue_t *, tommy_node *, void *) NONNULL(1,2,3);
void * queue_dequeue(queue_t *) NONNULL(1);
#define queue_size(Q) (Q)->size

#endif

