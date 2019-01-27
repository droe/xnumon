/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef ATOMIC_H
#define ATOMIC_H

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#define USE_STDC11
#elif defined(__GNUC__)
#define USE_GNUC
#elif defined(__APPLE__)
#define USE_LIBKERN
#else
#ifdef ATOMICS_UNSAFE
#warning No atomics implementation available, using workaround
#define USE_NONATOMIC
#else
#error No atomics implementation available and ATOMICS_UNSAFE not defined
#endif
#endif

#ifdef USE_STDC11
#include <stdatomic.h>
#define atomic32_t              volatile atomic_uint_fast32_t
#define atomic64_t              volatile atomic_uint_fast64_t
#define atomic32_fenced_inc(X)  atomic_fetch_add(X, 1)
#define atomic64_fenced_inc(X)  atomic_fetch_add(X, 1)
#define atomic32_fenced_dec(X)  atomic_fetch_sub(X, 1)
#define atomic64_fenced_dec(X)  atomic_fetch_sub(X, 1)
#define atomic32_fenced_load(X) atomic_load(X)
#define atomic64_fenced_load(X) atomic_load(X)
#define ATOMIC_RETURN_OLD
#endif

#ifdef USE_GNUC
#include <stdint.h>
#define atomic32_t              volatile uint32_t
#define atomic64_t              volatile uint64_t
#define atomic32_fenced_inc(X)  __sync_add_and_fetch(X, 1)
#define atomic64_fenced_inc(X)  __sync_add_and_fetch(X, 1)
#define atomic32_fenced_dec(X)  __sync_sub_and_fetch(X, 1)
#define atomic64_fenced_dec(X)  __sync_sub_and_fetch(X, 1)
inline atomic32_t
atomic32_fenced_load(atomic32_t *ptr) {
	atomic32_t x;
	__sync_synchronize();
	x = *ptr;
	__sync_synchronize();
	return x;
}
inline atomic64_t
atomic64_fenced_load(atomic64_t *ptr) {
	atomic64_t x;
	__sync_synchronize();
	x = *ptr;
	__sync_synchronize();
	return x;
}
#define ATOMIC_RETURN_OLD
#endif

#ifdef USE_LIBKERN
#include <libkern/OSAtomic.h>
#define atomic32_t              volatile int32_t
#define atomic64_t              volatile int64_t
#define atomic32_fast_inc(X)    OSAtomicIncrement32(X)
#define atomic64_fast_inc(X)    OSAtomicIncrement64(X)
#define atomic32_fast_dec(X)    OSAtomicDecrement32(X)
#define atomic64_fast_dec(X)    OSAtomicDecrement64(X)
#define atomic32_fenced_inc(X)  OSAtomicIncrement32Barrier(X)
#define atomic64_fenced_inc(X)  OSAtomicIncrement64Barrier(X)
#define atomic32_fenced_dec(X)  OSAtomicDecrement32Barrier(X)
#define atomic64_fenced_dec(X)  OSAtomicDecrement64Barrier(X)
#define atomic32_fenced_load(X) OSAtomicAdd32Barrier(0, X)
#define atomic64_fenced_load(X) OSAtomicAdd64Barrier(0, X)
#define ATOMIC_RETURN_NEW
#endif

#ifdef USE_NONATOMIC
#define atomic32_t              volatile uint32_t
#define atomic64_t              volatile uint64_t
#define atomic32_fenced_inc(X)  ((*(X))++)
#define atomic64_fenced_inc(X)  ((*(X))++)
#define atomic32_fenced_dec(X)  ((*(X))--)
#define atomic64_fenced_dec(X)  ((*(X))--)
#define atomic32_fenced_load(X) (*(X))
#define atomic64_fenced_load(X) (*(X))
#define ATOMIC_RETURN_OLD
#endif

#ifndef atomic32_fast_inc
#define atomic32_fast_inc(X)    atomic32_fenced_inc(X)
#define atomic64_fast_inc(X)    atomic64_fenced_inc(X)
#define atomic32_fast_dec(X)    atomic32_fenced_dec(X)
#define atomic64_fast_dec(X)    atomic64_fenced_dec(X)
#endif

#define atomic32_inc(X)         atomic32_fenced_inc(X)
#define atomic64_inc(X)         atomic64_fenced_inc(X)
#define atomic32_dec(X)         atomic32_fenced_dec(X)
#define atomic64_dec(X)         atomic64_fenced_dec(X)
#define atomic32_load(X)        atomic32_fenced_load(X)
#define atomic64_load(X)        atomic64_fenced_load(X)

#if defined(ATOMIC_RETURN_OLD)
#define atomic32_dec_test0(X)   (atomic32_dec(X) == 1)
#define atomic64_dec_test0(X)   (atomic64_dec(X) == 1)
#elif defined(ATOMIC_RETURN_NEW)
#define atomic32_dec_test0(X)   (atomic32_dec(X) == 0)
#define atomic64_dec_test0(X)   (atomic64_dec(X) == 0)
#else
#error Neither ATOMIC_RETURN_OLD nor ATOMIC_RETURN_NEW is defined
#endif

#endif

