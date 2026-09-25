/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 the openrosetta / fex_macos contributors. See vcpu_el1.h for the full MIT text.
 * vel1_pool: see vel1_pool.h. */
#include "vel1_pool.h"

#include <string.h>
#include <time.h>

uint64_t vel1_pool_now_ns(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }

int vel1_pool_init(vel1_pool* p, const vel1_pool_cfg* cfg) {
  if (!p || !cfg || cfg->slots == 0 || cfg->slots > 63 || cfg->low_water > cfg->slots || cfg->quantum_ns == 0)
    return VEL1_POOL_E_ARG;
  memset(p, 0, sizeof *p);
  if (pthread_mutex_init(&p->mu, NULL) || pthread_cond_init(&p->mon_cv, NULL)) return VEL1_POOL_E_THREAD;
  p->cfg = *cfg;
  p->free = cfg->slots;
  p->inited = true;
  return VEL1_POOL_OK;
}

int vel1_pool_destroy(vel1_pool* p) {
  if (!p || !p->inited) return VEL1_POOL_E_ARG;
  pthread_mutex_lock(&p->mu);
  const bool busy = p->members || p->mon_running;
  pthread_mutex_unlock(&p->mu);
  if (busy) return VEL1_POOL_E_STATE;
  pthread_cond_destroy(&p->mon_cv);
  pthread_mutex_destroy(&p->mu);
  p->inited = false;
  return VEL1_POOL_OK;
}

int vel1_pool_member_init(vel1_pool* p, vel1_pool_member* m, uint32_t flags) {
  if (!p || !p->inited || !m) return VEL1_POOL_E_ARG;
  /* Already registered: the memset below would cut p->all. Found by address in the list, not by m->registered, which
     is garbage in a member that was never initialised. */
  pthread_mutex_lock(&p->mu);
  for (const vel1_pool_member* x = p->all; x; x = x->next_all)
    if (x == m) {
      pthread_mutex_unlock(&p->mu);
      return VEL1_POOL_E_STATE;
    }
  pthread_mutex_unlock(&p->mu);
  memset(m, 0, sizeof *m);
  if (pthread_cond_init(&m->cv, NULL)) return VEL1_POOL_E_THREAD;
  atomic_store(&m->flags, flags);
  pthread_mutex_lock(&p->mu);
  m->next_all = p->all;
  if (p->all) p->all->prev_all = m;
  p->all = m;
  m->registered = true;
  ++p->members;
  pthread_mutex_unlock(&p->mu);
  return VEL1_POOL_OK;
}

int vel1_pool_member_fini(vel1_pool* p, vel1_pool_member* m) {
  if (!p || !m || !m->registered) return VEL1_POOL_E_ARG;
  pthread_mutex_lock(&p->mu);
  if (m->holds || m->queued) {
    pthread_mutex_unlock(&p->mu);
    return VEL1_POOL_E_STATE;
  }
  if (m->prev_all) m->prev_all->next_all = m->next_all;
  else p->all = m->next_all;
  if (m->next_all) m->next_all->prev_all = m->prev_all;
  m->registered = false;
  --p->members;
  pthread_mutex_unlock(&p->mu);
  pthread_cond_destroy(&m->cv);
  return VEL1_POOL_OK;
}

void vel1_pool_set_flags(vel1_pool_member* m, uint32_t flags) { atomic_store(&m->flags, flags); }
uint32_t vel1_pool_add_flags(vel1_pool_member* m, uint32_t flags) { return atomic_fetch_or(&m->flags, flags); }
uint32_t vel1_pool_clear_flags(vel1_pool_member* m, uint32_t flags) { return atomic_fetch_and(&m->flags, ~flags); }

int vel1_pool_acquire(vel1_pool* p, vel1_pool_member* m) {
  if (!p || !m || !m->registered) return VEL1_POOL_E_ARG;
  pthread_mutex_lock(&p->mu);
  if (m->holds || m->queued) {
    pthread_mutex_unlock(&p->mu);
    return VEL1_POOL_E_STATE;
  }
  ++p->st.acquires;
  if (p->free > 0 && !p->wait_head) { /* never overtake a waiter */
    --p->free;
    ++p->holders;
    m->holds = true;
    pthread_mutex_unlock(&p->mu);
    return VEL1_POOL_OK;
  }
  ++p->st.acquire_waits;
  m->queued = true;
  m->granted = false;
  m->next_wait = NULL;
  m->wait_start_ns = vel1_pool_now_ns();
  if (p->wait_tail) p->wait_tail->next_wait = m;
  else {
    p->wait_head = m;
    pthread_cond_signal(&p->mon_cv); /* the first waiter: wake the monitor from its idle (untimed) wait */
  }
  p->wait_tail = m;
  while (!m->granted) pthread_cond_wait(&m->cv, &p->mu); /* granted is set under mu: no lost wakeup */
  const uint64_t w = vel1_pool_now_ns() - m->wait_start_ns;
  p->st.total_wait_ns += w;
  if (w > p->st.max_wait_ns) p->st.max_wait_ns = w;
  m->queued = false;
  m->wait_start_ns = 0;
  m->holds = true; /* the releaser moved the slot to us: free and holders were not touched in between */
  pthread_mutex_unlock(&p->mu);
  return VEL1_POOL_OK;
}

int vel1_pool_release(vel1_pool* p, vel1_pool_member* m) {
  if (!p || !m || !m->registered) return VEL1_POOL_E_ARG;
  pthread_mutex_lock(&p->mu);
  if (!m->holds) {
    pthread_mutex_unlock(&p->mu);
    return VEL1_POOL_E_STATE;
  }
  m->holds = false;
  atomic_store(&m->run_since_ns, 0);
  atomic_store(&m->preempt, false); /* R7: the slot is given back: a pending preempt is moot */
  atomic_store(&m->preempt_since_ns, 0);
  atomic_store(&m->block_since_ns, 0); /* R15: no longer a blocked holder */
  ++p->st.releases;
  vel1_pool_member* w = p->wait_head;
  if (w) { /* direct handoff: the slot stays counted in holders, now for w */
    p->wait_head = w->next_wait;
    if (!p->wait_head) p->wait_tail = NULL;
    w->next_wait = NULL;
    w->granted = true;
    pthread_cond_signal(&w->cv);
  } else {
    --p->holders;
    ++p->free;
  }
  pthread_mutex_unlock(&p->mu);
  return VEL1_POOL_OK;
}

bool vel1_pool_should_release(vel1_pool* p, vel1_pool_member* m) {
  if (!p || !m || !m->registered) return false;
  if (atomic_load(&m->flags) & (VEL1_POOL_EXEMPT | VEL1_POOL_NEVER_RELEASE)) return false;
  pthread_mutex_lock(&p->mu);
  const bool holds = m->holds, waiters = p->wait_head != NULL;
  const uint32_t free_now = p->free;
  pthread_mutex_unlock(&p->mu);
  if (!holds) return false;
  if (waiters) return true;                                          /* hard */
  if (free_now < p->cfg.low_water) return m->have_avg && m->wait_avg_ns >= p->cfg.sleepy_ns; /* soft */
  return false;                                                      /* none */
}

void vel1_pool_note_wait(vel1_pool* p, vel1_pool_member* m, uint64_t ns) {
  (void)p;
  if (!m) return;
  if (!m->have_avg) {
    m->wait_avg_ns = ns;
    m->have_avg = true;
  } else {
    m->wait_avg_ns = m->wait_avg_ns - m->wait_avg_ns / 4 + ns / 4; /* EWMA, weight 1/4 */
  }
}

void vel1_pool_get_stats(vel1_pool* p, vel1_pool_stats* s) {
  pthread_mutex_lock(&p->mu);
  *s = p->st;
  s->free_now = p->free;
  s->holders_now = p->holders;
  uint32_t n = 0;
  for (vel1_pool_member* w = p->wait_head; w; w = w->next_wait) ++n;
  s->waiters_now = n;
  pthread_mutex_unlock(&p->mu);
}

void vel1_pool_note_run_begin(vel1_pool_member* m, uint64_t now_ns) { atomic_store(&m->run_since_ns, now_ns ? now_ns : 1); }
void vel1_pool_note_run_end(vel1_pool_member* m) { atomic_store(&m->run_since_ns, 0); }
bool vel1_pool_take_preempt(vel1_pool_member* m) {
  if (!atomic_exchange(&m->preempt, false)) return false;
  /* Lock-free (no pool argument). A re-kick racing this can leave preempt set with preempt_since_ns 0; the only
   * effect is one early re-kick at the next monitor tick, which the next take consumes. */
  atomic_store(&m->preempt_since_ns, 0);
  return true;
}

/* the oldest waiter has waited a quantum: the precondition of both preemption and R15's unblock */
static bool head_waited_locked(const vel1_pool* p, uint64_t now) {
  const vel1_pool_member* h = p->wait_head;
  return h && now >= h->wait_start_ns && now - h->wait_start_ns >= p->cfg.quantum_ns;
}

/* the victim pick_victim would choose, without marking it */
static vel1_pool_member* find_victim_locked(vel1_pool* p, uint64_t now) {
  vel1_pool_member* best = NULL;
  uint64_t best_since = 0;
  for (vel1_pool_member* m = p->all; m; m = m->next_all) {
    if (!m->holds) continue;
    if (atomic_load(&m->flags) & (VEL1_POOL_EXEMPT | VEL1_POOL_NEVER_RELEASE)) continue;
    const uint64_t since = atomic_load(&m->run_since_ns);
    if (!since || now < since || now - since < p->cfg.quantum_ns) continue;
    if (atomic_load(&m->preempt)) { /* R9: pending; re-kick only once it has been pending a quantum (lost kick) */
      const uint64_t ps = atomic_load(&m->preempt_since_ns);
      if (now < ps || now - ps < p->cfg.quantum_ns) continue;
    }
    if (!best || since < best_since) {
      best = m;
      best_since = since;
    }
  }
  return best;
}

static vel1_pool_member* pick_locked(vel1_pool* p, uint64_t now) {
  if (!head_waited_locked(p, now)) return NULL;
  vel1_pool_member* best = find_victim_locked(p, now);
  if (best) {
    atomic_store(&best->preempt_since_ns, now ? now : 1); /* before the flag: take_preempt clears after it */
    atomic_store(&best->preempt, true);
    ++p->st.preempts; /* a re-kick counts too */
  }
  return best;
}

vel1_pool_member* vel1_pool_pick_victim(vel1_pool* p, uint64_t now_ns) {
  pthread_mutex_lock(&p->mu);
  vel1_pool_member* v = pick_locked(p, now_ns);
  pthread_mutex_unlock(&p->mu);
  return v;
}

void vel1_pool_note_block_begin(vel1_pool_member* m, uint64_t now_ns) { atomic_store(&m->block_since_ns, now_ns ? now_ns : 1); }
void vel1_pool_note_block_end(vel1_pool_member* m) { atomic_store(&m->block_since_ns, 0); }

/* R15: the longest-blocked holder that is neither EXEMPT nor NEVER_RELEASE and was not unblocked in the last quantum,
   once the oldest waiter has waited a quantum and no running holder is eligible as a victim. */
static vel1_pool_member* unblock_locked(vel1_pool* p, uint64_t now) {
  if (!head_waited_locked(p, now) || find_victim_locked(p, now)) return NULL;
  vel1_pool_member* best = NULL;
  uint64_t best_since = 0;
  for (vel1_pool_member* m = p->all; m; m = m->next_all) {
    if (!m->holds) continue;
    if (atomic_load(&m->flags) & (VEL1_POOL_EXEMPT | VEL1_POOL_NEVER_RELEASE)) continue;
    const uint64_t since = atomic_load(&m->block_since_ns);
    if (!since) continue;
    if (m->unblock_ns && now >= m->unblock_ns && now - m->unblock_ns < p->cfg.quantum_ns) continue;
    if (!best || since < best_since) {
      best = m;
      best_since = since;
    }
  }
  if (best) {
    best->unblock_ns = now ? now : 1;
    ++p->st.unblocks;
  }
  return best;
}

vel1_pool_member* vel1_pool_pick_unblock(vel1_pool* p, uint64_t now_ns) {
  pthread_mutex_lock(&p->mu);
  vel1_pool_member* u = unblock_locked(p, now_ns);
  pthread_mutex_unlock(&p->mu);
  return u;
}

static void* monitor_main(void* arg) {
  vel1_pool* p = arg;
  pthread_mutex_lock(&p->mu);
  while (!p->mon_stop) {
    if (!p->wait_head) { /* idle: nothing to preempt or unblock for; acquire signals the first waiter */
      pthread_cond_wait(&p->mon_cv, &p->mu);
      ++p->st.monitor_wakeups;
      continue;
    }
    const uint64_t step = p->cfg.quantum_ns / 4 ? p->cfg.quantum_ns / 4 : 1;
    const struct timespec ts = {(time_t)(step / 1000000000ull), (long)(step % 1000000000ull)};
    pthread_cond_timedwait_relative_np(&p->mon_cv, &p->mu, &ts); /* relative: a wall-clock step cannot stall it */
    ++p->st.monitor_wakeups;
    if (p->mon_stop) break;
    const uint64_t now = vel1_pool_now_ns();
    vel1_pool_member* v = pick_locked(p, now);
    if (v) p->kick(v, p->kick_arg); /* under mu: member_fini cannot free v meanwhile */
    else if (p->unblock) {          /* R15: no running victim; a holder blocked without releasing may be the cause */
      vel1_pool_member* u = unblock_locked(p, now);
      if (u) p->unblock(u, p->kick_arg); /* under mu, as kick */
    }
  }
  pthread_mutex_unlock(&p->mu);
  return NULL;
}

int vel1_pool_monitor_start(vel1_pool* p, vel1_pool_kick_fn kick, void* arg) {
  return vel1_pool_monitor_start2(p, kick, NULL, arg);
}

int vel1_pool_monitor_start2(vel1_pool* p, vel1_pool_kick_fn kick, vel1_pool_kick_fn unblock, void* arg) {
  if (!p || !p->inited || !kick) return VEL1_POOL_E_ARG;
  pthread_mutex_lock(&p->mu);
  if (p->mon_running) {
    pthread_mutex_unlock(&p->mu);
    return VEL1_POOL_E_STATE;
  }
  p->kick = kick;
  p->unblock = unblock;
  p->kick_arg = arg;
  p->mon_stop = false;
  p->mon_running = pthread_create(&p->mon, NULL, monitor_main, p) == 0;
  const bool ok = p->mon_running;
  pthread_mutex_unlock(&p->mu);
  return ok ? VEL1_POOL_OK : VEL1_POOL_E_THREAD;
}

void vel1_pool_monitor_stop(vel1_pool* p) {
  pthread_mutex_lock(&p->mu);
  if (!p->mon_running) {
    pthread_mutex_unlock(&p->mu);
    return;
  }
  p->mon_stop = true;
  pthread_cond_signal(&p->mon_cv);
  const pthread_t t = p->mon;
  pthread_mutex_unlock(&p->mu);
  pthread_join(t, NULL);
  pthread_mutex_lock(&p->mu);
  p->mon_running = false;
  pthread_mutex_unlock(&p->mu);
}

