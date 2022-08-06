/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_GENERIC_XCMPXCHG_H
#define __ASM_GENERIC_XCMPXCHG_H
/*
 * xcmpxchg: Exclusive cmpxchg
 * (C) 2022, Hyeonggon Yoo <42.hyeyoo@gmail.com>
 */

#include <asm-generic/cmpxchg-local.h>

/* Use LL/SC cmpxchg when arch provides both */
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE_LOCAL) && \
	!defined(CONFIG_HAVE_LL_SC_CMPXCHG)
#define USE_CMPXCHG_DOUBLE_LOCAL
#endif

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
struct xcmpxchg {
	void *value;
	unsigned long tid;
};
#else
struct xcmpxchg {
	void *value;
};
#endif

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline void xcmpxchg_init(struct xcmpxchg *s, int cpu)
{
	s->tid = cpu;
	s->value = 0;
}
#else
static inline void xcmpxchg_init(struct xcmpxchg *s, int cpu)
{
	s->value = 0;
}
#endif

#ifdef CONFIG_PREEMPTION
/*
 * Calculate the next globally unique transaction for disambiguation
 * during cmpxchg. The transactions start with the cpu number and are then
 * incremented by CONFIG_NR_CPUS.
 */
#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
#else
/*
 * No preemption supported therefore also no need to check for
 * different cpus.
 */
#define TID_STEP 1
#endif

static inline unsigned long next_tid(unsigned long tid)
{
	return tid + TID_STEP;
}

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline void xcmpxchg_set(struct xcmpxchg *s, void *value)
{
	s->value = value;
	s->tid = next_tid(s->tid);
}
#else
static inline void xcmpxchg_set(struct xcmpxchg *s, void *value)
{
	s->value = value;
}
#endif

static inline void *xcmpxchg_read(struct xcmpxchg *s)
{
	return READ_ONCE(s->value);
}

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline unsigned long xcmpxchg_read_tid(struct xcmpxchg *s)
{
	return READ_ONCE(s->tid);
}
#else
static inline unsigned long xcmpxchg_read_tid(struct xcmpxchg *s)
{
	return 0;
}
#endif

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline void xcmpxchg_next_tid(struct xcmpxchg *s)
{
	s->tid = next_tid(s->tid);
}
#else
static inline void xcmpxchg_next_tid(struct xcmpxchg *s) { }
#endif

/* Set value without updating transaction id */
#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline void __xcmpxchg_set(struct xcmpxchg *s, void *value)
{
	s->value = value;
}
#else
static inline void __xcmpxchg_set(struct xcmpxchg *s, void *value) {
	xcmpxchg_set(s, value);
}
#endif

#ifdef USE_CMPXCHG_DOUBLE_LOCAL
static inline void *xcmpxchg_local(struct xcmpxchg *s,
				   void *old, void *new,
				   unsigned long tid)
{
	if (cmpxchg_double_local(&s->value, &s->tid,
				 old, tid,
				 new, next_tid(tid)))
		return old;
	return ERR_PTR(-EAGAIN);
}
#elif defined(CONFIG_HAVE_LL_SC_CMPXCHG)
static inline void *xcmpxchg_local(struct xcmpxchg *s,
				  void *old, void *new,
				  unsigned long tid)
{
	return cmpxchg_local(&s->value, old, new);
}
#else
static inline void *xcmpxchg_local(struct xcmpxchg *s,
				   void *old, void *new,
				   unsigned long tid)
{
	return __generic_cmpxchg_local(&s->value,
				       (unsigned long)old,
				       (unsigned long)new,
				       sizeof(unsigned long));
#endif

#endif /* !ASM_GENERIC_XCMPXCHG_H */
