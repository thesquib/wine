/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 the openrosetta / fex_macos contributors. See vcpu_el1.h for the full MIT text.
 *
 * vel1_pool: the vCPU slot pool for M:N by release-on-block (openrosetta
 * docs/superpowers/specs/2026-09-25-mn-release-on-block-design.md). Pure host C: no hv_* call, no vcpu_el1
 * dependency. One pool per process; one member per Windows thread, embedded in the caller's per-thread struct.
 *
 *   acquire   blocks until the member holds a slot. FIFO: a released slot goes directly to the oldest waiter.
 *   release   gives the slot back (to the oldest waiter, if any).
 *   should_release   the policy at a block point (spec §4): none (free >= low_water, no waiters) -> false;
 *             soft (free < low_water, no waiters) -> only if the member's wait average >= sleepy_ns;
 *             hard (any waiter) -> true. EXEMPT / NEVER_RELEASE members -> always false.
 *   note_wait feeds the member's wait average (EWMA, 1/4 weight; the first sample sets it).
 *
 * Threading: acquire/release/should_release/note_wait/note_block_begin/note_block_end/member_fini are called by the
 * member's own thread only. set_flags/add_flags/clear_flags may be called by any thread. Every function is safe
 * against every other member's calls.
 */
#ifndef VEL1_POOL_H
#define VEL1_POOL_H
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { VEL1_POOL_OK = 0, VEL1_POOL_E_ARG = -1, VEL1_POOL_E_STATE = -2, VEL1_POOL_E_THREAD = -3 };
enum { VEL1_POOL_EXEMPT = 1u, VEL1_POOL_NEVER_RELEASE = 2u };

typedef struct {
  uint32_t slots;      /* 1..63: 64 minus the vCPUs the process creates OUTSIDE the pool (Wine: the parked TLBI
                          executor -> 63). Create those before the pool can hand out its last slot (at process
                          start, before the first acquire): the count assumes they exist, and a lazy re-acquire
                          cannot recover from a create that fails at HVF's 64 */
  uint32_t low_water;  /* 0..slots */
  uint64_t sleepy_ns;  /* soft pressure: members whose wait average is at least this release */
  uint64_t quantum_ns; /* > 0: preemption (Task 3) */
} vel1_pool_cfg;
#define VEL1_POOL_CFG_DEFAULT {63u, 8u, 4000000ull, 2000000ull}

typedef struct vel1_pool_member {
  /* private: the pool's */
  struct vel1_pool_member *next_wait, *next_all, *prev_all;
  pthread_cond_t cv;
  uint64_t wait_start_ns, wait_avg_ns;
  bool have_avg, holds, queued, granted, registered;
  _Atomic uint32_t flags;
  _Atomic uint64_t run_since_ns; /* Task 3: 0 = not in vel1_run */
  _Atomic bool preempt;          /* Task 3 */
  _Atomic uint64_t preempt_since_ns; /* R9: when preempt was last set (0 = not pending); appended */
  _Atomic uint64_t block_since_ns;   /* R15: note_block_begin's time while blocked HOLDING a slot (0 = not); appended */
  uint64_t unblock_ns;               /* R15: when the monitor last unblocked this member (0 = never; under mu) */
} vel1_pool_member;

typedef struct {
  uint64_t acquires, acquire_waits, releases, preempts, max_wait_ns, total_wait_ns;
  uint32_t free_now, waiters_now, holders_now;
  uint64_t unblocks;        /* R15: unblock calls (appended) */
  uint64_t monitor_wakeups; /* the monitor thread's returns from its waits (0 while idle: no waiter) (appended) */
} vel1_pool_stats;

typedef void (*vel1_pool_kick_fn)(vel1_pool_member* m, void* arg); /* Task 3 */

typedef struct vel1_pool {
  /* private */
  pthread_mutex_t mu;
  vel1_pool_cfg cfg;
  uint32_t free, holders, members;
  vel1_pool_member *wait_head, *wait_tail, *all;
  vel1_pool_stats st;
  pthread_t mon;
  pthread_cond_t mon_cv;
  bool mon_running, mon_stop, inited;
  vel1_pool_kick_fn kick;
  void* kick_arg;
  vel1_pool_kick_fn unblock; /* R15, optional (appended) */
} vel1_pool;

uint64_t vel1_pool_now_ns(void); /* CLOCK_UPTIME_RAW, ns */
int vel1_pool_init(vel1_pool* p, const vel1_pool_cfg* cfg);  /* E_ARG: slots 0 or > 63, low_water > slots, quantum 0 */
int vel1_pool_destroy(vel1_pool* p);                         /* E_STATE: members registered or monitor running */
int vel1_pool_member_init(vel1_pool* p, vel1_pool_member* m, uint32_t flags); /* E_STATE: already registered in p */
int vel1_pool_member_fini(vel1_pool* p, vel1_pool_member* m); /* E_STATE while holding or queued */
void vel1_pool_set_flags(vel1_pool_member* m, uint32_t flags);  /* REPLACES every flag: set_flags(EXEMPT) clears
                                                                   a NEVER_RELEASE; prefer add_flags/clear_flags */
uint32_t vel1_pool_add_flags(vel1_pool_member* m, uint32_t flags);   /* atomic OR; returns the flags before */
uint32_t vel1_pool_clear_flags(vel1_pool_member* m, uint32_t flags); /* atomic AND NOT; returns the flags before */
int vel1_pool_acquire(vel1_pool* p, vel1_pool_member* m);     /* E_STATE if already holding or queued */
int vel1_pool_release(vel1_pool* p, vel1_pool_member* m);     /* E_STATE if not holding */
bool vel1_pool_should_release(vel1_pool* p, vel1_pool_member* m);
void vel1_pool_note_wait(vel1_pool* p, vel1_pool_member* m, uint64_t ns);
void vel1_pool_get_stats(vel1_pool* p, vel1_pool_stats* s);

/* Preemption (spec: a thread can wake without a vCPU while holding a guest spinlock that every slot holder spins
 * on; only a kick frees a slot then).
 *
 * pick_victim returns NULL unless the oldest waiter has waited >= quantum_ns; otherwise the holder with the oldest
 * run_since_ns among members that hold, are in a run (run_since_ns != 0), have run >= quantum_ns, and are neither
 * EXEMPT nor NEVER_RELEASE, and either have no preempt pending or have had one pending for >= quantum_ns (R9: a
 * re-kick, so a lost or consumed kick is retried). It sets the victim's preempt flag and preempt_since_ns (and counts
 * stats.preempts, re-kicks included).
 *
 * The monitor thread sleeps untimed while no thread waits for a slot (no cost in plain 1:1 use); acquire wakes it
 * when it queues onto an empty FIFO, and it then wakes every quantum_ns / 4 (a relative timed wait: a wall-clock step
 * cannot stall it) until the FIFO is empty again. For a victim it calls kick(victim, arg) WITH THE POOL LOCK HELD
 * (so member_fini cannot free the member mid-kick); kick must not call into the pool, must not take a lock any
 * thread holds while calling a vel1_pool function, and must not block (an ABBA hazard against p->mu, and a blocked
 * kick stalls every other thread's pool call). Wine's kick sets nothing else and calls vel1_kick_remote on the
 * victim's vCPU. NOTE: vel1_kick_remote waits for the vCPU's life_lock, which
 * vel1_vcpu_destroy holds across hv_vcpu_destroy (up to ~1.9 ms under HVF's serialised destroys, rung RM), so a pick
 * that races the victim's release (it leaves vel1_run and destroys) can stall every pool call that long. Rare, bounded.
 *
 * The owner calls vel1_pool_take_preempt after EVERY vel1_run return (one atomic exchange), whatever the exit: the
 * kick itself can be consumed elsewhere (vcpu_el1.h D15's vel1_kick_take after every vel1_run return, FLAG_ONLY, or
 * the G3 CANCELED-on-stub re-entry). If it returns true, the owner releases (ctx save, destroy, vel1_pool_release),
 * then vel1_pool_acquire (back of the FIFO), create, restore. take_preempt clears the flag and preempt_since_ns.
 * vel1_pool_release clears both too (with run_since_ns, under the pool lock): a victim that gives its slot back at a
 * block point before it took the preempt is neither immune to later preemption nor requeued on a later return.
 *
 * Note for Wine: the monitor thread is a plain pthread; Wine should create it with all signals blocked, as it does
 * for vel1's kicker and the TLBI executor (create_thread_no_signals), i.e. call vel1_pool_monitor_start from a
 * thread whose mask blocks everything, or block signals first.
 *
 * monitor_start: E_ARG (no pool / no kick), E_STATE (already running), E_THREAD (pthread_create failed).
 * monitor_stop: joins the monitor; idempotent. vel1_pool_destroy refuses (E_STATE) while the monitor runs.
 *
 * Blocked holders (ruling R15). A holder that blocks WITHOUT releasing (none or soft pressure at its block point) is
 * neither running nor waiting, so preemption cannot see it: if every holder waits on a thread that holds no slot (idle
 * workers waiting on a main thread that released at a frame-pacing sleep), the process deadlocks. The owner brackets
 * such a wait with note_block_begin (just before it, only when it kept its slot) and note_block_end (after it;
 * idempotent; vel1_pool_release clears it too). With an unblock callback (vel1_pool_monitor_start2), when the oldest
 * waiter has waited >= quantum_ns and no running holder is eligible as a victim (pick_victim's rules, pending
 * preempts included), the monitor calls unblock(member, arg), ALSO WITH THE POOL LOCK HELD (it must not call into
 * the pool, must not take a lock any thread holds while calling a vel1_pool function, and must not block — the same
 * hazard as kick, above), on the holder that has been blocked longest among those that hold, are blocked, and are
 * neither EXEMPT nor NEVER_RELEASE, at most once per quantum_ns per member (stats.unblocks). Wine implements unblock
 * by interrupting that thread's wait so it re-runs its block point, where should_release (hard pressure: a waiter
 * exists) releases; it then waits on without a slot. WITHOUT an unblock callback (vel1_pool_monitor_start) this
 * deadlock remains possible. pick_unblock is the monitor's choice as a pure function (explicit clock, for tests):
 * NULL unless the oldest waiter has waited a quantum and no running victim is eligible; it records the unblock time
 * and counts stats.unblocks.
 *
 * SIGUSR1 limit (do not overclaim unblock here): a holder suspended INSIDE Wine's usr1_handler (send_thread_signal's
 * suspend) is a different case from the note_block-bracketed wait above, and unblock CANNOT rescue it — no pool
 * call, and no vel1_ctx_save/vel1_vcpu_destroy, is safe or even possible from inside a signal handler. Such a holder
 * is freed only by the ordinary kick path: it must still own a vCPU and take a KICK exit through vel1 itself. Do not
 * bracket a usr1_handler suspend with note_block_begin/end expecting unblock to reach it.
 *
 * Spurious unblock: note_block_end clears block_since_ns without the pool lock (lock-free), so a pick_unblock
 * running concurrently on the monitor thread can still choose a member that has, in that same instant, already
 * called note_block_end and moved on. The resulting unblock then lands on that member's NEXT block-bracketed wait,
 * not the one it targeted. Every block site must therefore tolerate an interrupted or spurious return regardless of
 * cause, and simply re-check its own wait condition rather than assume an unblock always means what it was aimed
 * at. */
void vel1_pool_note_run_begin(vel1_pool_member* m, uint64_t now_ns);    /* owning thread, just before vel1_run */
void vel1_pool_note_run_end(vel1_pool_member* m);                       /* owning thread, just after it returns */
vel1_pool_member* vel1_pool_pick_victim(vel1_pool* p, uint64_t now_ns); /* sets the victim's preempt flag */
bool vel1_pool_take_preempt(vel1_pool_member* m);                       /* owning thread, after EVERY vel1_run return */
int vel1_pool_monitor_start(vel1_pool* p, vel1_pool_kick_fn kick, void* arg); /* = monitor_start2(p, kick, NULL, arg) */
void vel1_pool_monitor_stop(vel1_pool* p);
void vel1_pool_note_block_begin(vel1_pool_member* m, uint64_t now_ns);   /* owning thread: keeps its slot across a wait */
void vel1_pool_note_block_end(vel1_pool_member* m);                     /* owning thread, after the wait; idempotent */
vel1_pool_member* vel1_pool_pick_unblock(vel1_pool* p, uint64_t now_ns); /* records the unblock time; counts it */
int vel1_pool_monitor_start2(vel1_pool* p, vel1_pool_kick_fn kick, vel1_pool_kick_fn unblock, void* arg); /* unblock
                                                                          may be NULL; errors as monitor_start */

#ifdef __cplusplus
}
#endif
#endif
