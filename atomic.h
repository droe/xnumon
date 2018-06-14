/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef ATOMIC_H
#define ATOMIC_H

#ifndef __STDC_NO_ATOMICS__
#define USE_STDC
#elif defined(__APPLE__)
#define USE_LIBKERN
#else
#warning No atomics implementation available
#define USE_NONATOMIC
#endif

#ifdef USE_STDC
#include <stdatomic.h>
#define atomic32_t volatile atomic_uint_fast32_t
#define atomic64_t volatile atomic_uint_fast64_t
#define atomic32_inc(X) atomic_fetch_add(X, 1)
#define atomic64_inc(X) atomic_fetch_add(X, 1)
#define atomic32_dec(X) atomic_fetch_sub(X, 1)
#define atomic64_dec(X) atomic_fetch_sub(X, 1)
#endif

#ifdef USE_LIBKERN
#include <libkern/OSAtomic.h>
#define atomic32_t volatile int32_t
#define atomic64_t volatile int64_t
#define atomic32_inc(X) OSAtomicIncrement32(X)
#define atomic64_inc(X) OSAtomicIncrement64(X)
#define atomic32_dec(X) OSAtomicDecrement32(X)
#define atomic64_dec(X) OSAtomicDecrement64(X)
#endif

#ifdef USE_NONATOMIC
#define atomic32_t volatile uint32_t
#define atomic64_t volatile uint64_t
#define atomic32_inc(X) ((*(X))++)
#define atomic64_inc(X) ((*(X))++)
#define atomic32_dec(X) ((*(X))--)
#define atomic64_dec(X) ((*(X))--)
#endif

#endif

