/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef POLICY_H
#define POLICY_H

int policy_task_sched_priority(void);

#if 0
int policy_thread_sched_priority(int);
#define TP_MAX 63
#define TP_HIGH 59
#define TP_NORM 31
#define TP_LOW  15
int policy_thread_sched_standard(void);
#endif

int policy_thread_diskio_important(void);
int policy_thread_diskio_standard(void);
int policy_thread_diskio_utility(void);

#endif

