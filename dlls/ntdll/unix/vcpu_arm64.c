/*
 * arm64 vCPU mode: the per-process VM, guest memory manager and TLB shootdown executor
 *
 * Copyright 2026 the proton-darwin contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * With PMW_VCPU=1 every Windows thread's user-mode code runs at EL1 in a Hypervisor.framework vCPU (openrosetta's
 * vcpu_el1, vendored in vcpu/), with guest VA == host VA and the stage-1 tables kept by openrosetta's gmm from
 * virtual.c's view tree. This file owns the per-process pieces: the VM, gmm and its stage-2 backend, the system
 * page (vector blob, TLBI stub, TLBI mailbox), the TLB shootdown executor and the KUSER_SHARED_DATA guest page.
 *
 * Design: proton-darwin docs/macos/vcpu-m1-wine-vcpu-mode-design-2026-09-23.md.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#if defined(__APPLE__) && defined(__aarch64__)

#include <dlfcn.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/vm_statistics.h>
#include <libkern/OSCacheControl.h>
#include <Hypervisor/Hypervisor.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/unixlib.h"
#include "unix_private.h"
#include "vcpu_arm64.h"
#include "vcpu/vel1_pool.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(vcpu);

/* the +syscall relay tracing of user callbacks (loader.c; the EL0 path calls them from asm) */
extern void trace_usercall( UINT id, ULONG_PTR *args, ULONG len );
extern void trace_userret( void *ret_ptr, ULONG len, NTSTATUS status, UINT id );

int vcpu_mode;
/* M:N (docs/macos/vcpu-mn-release-on-block-design-2026-09-25.md): threads share the pool's 63 vCPU slots and give
 * theirs back at a block point, so a process may run more than 63 threads. Default on; PMW_VCPU_MN=0 turns it off,
 * which is exactly the old one-vCPU-per-thread mode. */
static int vcpu_mn;
static vel1_pool vcpu_pool;
static _Atomic int prof_threads_live, prof_threads_peak;
static _Atomic uint64_t prof_rel_block, prof_rel_preempt;
static void vcpu_pool_line( char *buf, size_t size );  /* prof_thread, above its definition, prints it */
int vcpu_check_s2;
int vcpu_sect_alias;
int vcpu_shared_sections;  /* PMW_VCPU_SHARED_SECTIONS (default on, =0 off): shm-backed sections alias one object across processes */

#define VCPU_IPA_BITS      40
#define VCPU_PT_POOL_IPA   0x10000000ull            /* 256 MiB */
#define VCPU_PT_POOL_SIZE  (64ull << 20)
#define VCPU_DATA_IPA_LO   (1ull << 30)             /* 1 GiB */
#define VCPU_DATA_IPA_HI   (1ull << VCPU_IPA_BITS)
/* the guest-only mirror window of gmm's low-4GiB regions: above every host VA (47 bits), inside the 48-bit guest VA
 * space, so nothing on the host needs reserving (gmm README R6) */
#define VCPU_ALIAS_BASE    0x800000000000ull
#define VCPU_KUSER_VA      0x7ffe0000ull

/* the system page: one 16K host page, identity-mapped into the guest */
#define SYS_PAGE_SIZE      0x4000
#define SYS_BLOB_OFF       0x0000   /* vcpu_el1's vector table and stubs, stage-1 RX */
#define SYS_TLBI_OFF       0x1000   /* TLBI stub, stage-1 RX */
#define SYS_MAILBOX_OFF    0x2000   /* TLBI mailbox, stage-1 RW: [0] = count (0 = all), [1..] = VAs */
#define MAILBOX_MAX_VA     ((0x1000 / sizeof(uint64_t)) - 1)
#define VCPU_HVC_TLBI_DONE 0x8000
#define VCPU_HVC_PROBE_DONE 0x8001
#define SYS_PROBE_OFF      0x1800   /* selftest probe stub, in the TLBI stub's page */

static gmm_t *gmm;
static char *sys_page;
static void *kuser_host;
static atomic_int any_entered;  /* no TLBI is needed until some Windows vCPU has run */

/* The TLBI stub: x0 = the mailbox. Guest code, copied into the system page (never executed on the host). */
extern const uint8_t vcpu_tlbi_stub_start[], vcpu_tlbi_stub_end[];
__asm__( ".section __TEXT,__const\n\t"
         ".p2align 2\n\t"
         ".globl _vcpu_tlbi_stub_start\n\t"
         ".globl _vcpu_tlbi_stub_end\n"
         "_vcpu_tlbi_stub_start:\n\t"
         "dsb ish\n\t"
         "ldr x1, [x0]\n\t"
         "cbz x1, 2f\n\t"
         "add x2, x0, #8\n"
         "1:\tldr x3, [x2], #8\n\t"
         "lsr x3, x3, #12\n\t"            /* Xt = VA >> 12, ASID 0 (gmm descriptors are global) */
         "tlbi vale1is, x3\n\t"
         "subs x1, x1, #1\n\t"
         "b.ne 1b\n\t"
         "b 3f\n"
         "2:\ttlbi vmalle1is\n"
         "3:\tdsb ish\n\t"
         "isb\n\t"
         "hvc #0x8000\n\t"                 /* VCPU_HVC_TLBI_DONE, a HOSTCALL inside the stub page */
         "b .\n"
         "_vcpu_tlbi_stub_end:\n\t"
         ".text" );

/* The selftest probe: x0 = address, x1 = value. Reads [x0] into x3, then writes x1 to it. */
extern const uint8_t vcpu_probe_stub_start[], vcpu_probe_stub_end[];
__asm__( ".section __TEXT,__const\n\t"
         ".p2align 2\n\t"
         ".globl _vcpu_probe_stub_start\n\t"
         ".globl _vcpu_probe_stub_end\n"
         "_vcpu_probe_stub_start:\n\t"
         "ldr x3, [x0]\n\t"
         "str x1, [x0]\n\t"
         "hvc #0x8001\n\t"               /* VCPU_HVC_PROBE_DONE */
         "b .\n"
         "_vcpu_probe_stub_end:\n\t"
         ".text" );

static void vcpu_fatal( const char *fmt, ... ) __attribute__((noreturn, format(printf,1,2)));
static void vcpu_fatal( const char *fmt, ... )
{
    va_list args;

    fprintf( stderr, "wine: vCPU mode: " );
    va_start( args, fmt );
    vfprintf( stderr, fmt, args );
    va_end( args );
    exit( 1 );
}

static double ticks_to_us( uint64_t ticks )
{
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info( &tb );
    return (double)ticks * tb.numer / tb.denom / 1000.0;
}


/***********************************************************************
 *           vcpu_create
 *
 * vel1_vcpu_create with hardware TSO (ACTLR_EL1.EnTSO, vcpu_el1.h D3), all or none per process: the process's first
 * vCPU decides (an x86 emulator picks its memory-ordering scheme once per process), and a later vCPU that disagrees
 * is fatal, never a silent vCPU without TSO in a process whose emulator relies on it.
 */
static atomic_int tso_state;  /* 0: undecided, 1: every vCPU runs with EnTSO, -1: none does */

static int vcpu_create( vel1_vcpu *v, vel1_vcpu_cfg *cfg )
{
    int ret, have, state = atomic_load( &tso_state );

    if (state < 0)
    {
        cfg->flags |= VEL1_CFG_NO_ENTSO;
        return vel1_vcpu_create( v, cfg );
    }
    if ((ret = vel1_vcpu_create( v, cfg )) && ret != VEL1_E_ENTSO) return ret;
    have = ret ? -1 : 1;
    if (!state && atomic_compare_exchange_strong( &tso_state, &state, have ))
    {
        state = have;
        if (have < 0)
            fprintf( stderr, "wine: vCPU mode: ACTLR_EL1.EnTSO did not read back on the first vCPU: every vCPU of "
                     "this process runs WITHOUT hardware TSO (fine for arm64 code; x86 emulation needs software TSO)\n" );
    }
    if (state != have)
        vcpu_fatal( "ACTLR_EL1.EnTSO %s on this vCPU but %s on the process's first: a process's vCPUs must all "
                    "run with hardware TSO or all without\n", have > 0 ? "reads back" : "did not read back",
                    state > 0 ? "did" : "did not" );
    if (have > 0) return VEL1_OK;
    cfg->flags |= VEL1_CFG_NO_ENTSO;
    return vel1_vcpu_create( v, cfg );
}


/***********************************************************************
 * gmm stage-2 backend
 */
static uint32_t s2_map( void *host, uint64_t ipa, size_t size, int perm )
{
    hv_memory_flags_t flags = 0;

    if (perm & GMM_S2_R) flags |= HV_MEMORY_READ;
    if (perm & GMM_S2_W) flags |= HV_MEMORY_WRITE;
    if (perm & GMM_S2_X) flags |= HV_MEMORY_EXEC;
    if (vcpu_prof_interval)
    {
        uint64_t t0 = vcpu_prof_now();
        uint32_t ret = hv_vm_map( host, ipa, size, flags );
        vcpu_prof_add( VCPU_PROF_S2_MAP, vcpu_prof_now() - t0 );
        return ret;
    }
    return hv_vm_map( host, ipa, size, flags );
}

static uint32_t s2_unmap( uint64_t ipa, size_t size )
{
    if (vcpu_prof_interval)
    {
        uint64_t t0 = vcpu_prof_now();
        uint32_t ret = hv_vm_unmap( ipa, size );
        vcpu_prof_add( VCPU_PROF_S2_UNMAP, vcpu_prof_now() - t0 );
        return ret;
    }
    return hv_vm_unmap( ipa, size );
}


/***********************************************************************
 * TLB shootdown executor
 *
 * gmm's tlbi_sync must not return until no vCPU can use the old translations. A TLBI has to be executed by a vCPU
 * of this VM (the IS form broadcasts to the others), so one dedicated vCPU on its own thread runs the stub on
 * request. The executor is parked between requests; openrosetta measured ~5.8 us per request from idle.
 */
static pthread_mutex_t tlbi_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tlbi_cond = PTHREAD_COND_INITIALIZER;
static unsigned int tlbi_req, tlbi_done;
static int tlbi_status;  /* 0 ok; < 0 the executor failed (fatal for gmm) */
static int tlbi_ready;
static vel1_vcpu tlbi_vcpu;
static uint64_t tlbi_count, tlbi_ticks;

static int tlbi_run_once( vel1_vcpu *v, uint64_t mailbox )
{
    vel1_regs regs;
    vel1_exit e;
    vel1_exit_kind kind;
    int ret;

    memset( &regs, 0, sizeof(regs) );
    regs.x[0] = mailbox;
    if ((ret = vel1_resume_at( v, (uint64_t)sys_page + SYS_TLBI_OFF, 0 ))) return ret;
    if ((ret = vel1_regs_set( v, &regs, VEL1_R_X(0), 0 ))) return ret;
    kind = vel1_run( v, &e );
    if (kind != VEL1_EXIT_HOSTCALL || e.hvc_imm != VCPU_HVC_TLBI_DONE)
    {
        ERR( "TLBI stub: unexpected exit %s (err %d hv %#x esr %#llx elr %#llx)\n", vel1_exit_kind_name( kind ),
             e.err, e.hv_err, (unsigned long long)e.esr, (unsigned long long)e.elr );
        return -1;
    }
    return 0;
}

static void *tlbi_thread( void *arg )
{
    vel1_vcpu_cfg cfg;
    unsigned int seen = 0;
    int ret;

    memset( &cfg, 0, sizeof(cfg) );
    cfg.ttbr0 = gmm_ttbr0( gmm );
    cfg.blob_va = (uint64_t)sys_page + SYS_BLOB_OFF;
    cfg.pc = (uint64_t)sys_page + SYS_TLBI_OFF;
    cfg.x0 = (uint64_t)sys_page + SYS_MAILBOX_OFF;
    cfg.hostcall_lo = (uint64_t)sys_page + SYS_TLBI_OFF;
    cfg.hostcall_hi = cfg.hostcall_lo + 0x1000;
    ret = vcpu_create( &tlbi_vcpu, &cfg );

    pthread_mutex_lock( &tlbi_mutex );
    tlbi_status = ret ? -1 : 0;
    tlbi_ready = 1;
    pthread_cond_broadcast( &tlbi_cond );
    if (ret)
    {
        ERR( "TLBI executor: vel1_vcpu_create failed %d (hv %#x)\n", ret, tlbi_vcpu.last_hv_err );
        pthread_mutex_unlock( &tlbi_mutex );
        return NULL;
    }
    for (;;)
    {
        while (tlbi_req == seen) pthread_cond_wait( &tlbi_cond, &tlbi_mutex );
        seen = tlbi_req;
        if (tlbi_run_once( &tlbi_vcpu, (uint64_t)sys_page + SYS_MAILBOX_OFF )) tlbi_status = -1;
        tlbi_done = seen;
        pthread_cond_broadcast( &tlbi_cond );
    }
}

static uint64_t tlbi_initiator_count, tlbi_initiator_ticks, tlbi_initiator_refused;
static int tlbi_initiator( const uint64_t *va, size_t count, int all );  /* after struct vcpu_thread */

static int tlbi_sync_impl( void *ctx, const uint64_t *va, size_t count, int all );

static int tlbi_sync( void *ctx, const uint64_t *va, size_t count, int all )
{
    uint64_t t0;
    int ret;

    if (!vcpu_prof_interval) return tlbi_sync_impl( ctx, va, count, all );
    t0 = vcpu_prof_now();
    ret = tlbi_sync_impl( ctx, va, count, all );
    vcpu_prof_add( VCPU_PROF_TLBI, vcpu_prof_now() - t0 );
    return ret;
}

static int tlbi_sync_impl( void *ctx, const uint64_t *va, size_t count, int all )
{
    uint64_t *mailbox = (uint64_t *)(sys_page + SYS_MAILBOX_OFF);
    uint64_t start;
    unsigned int req;
    int ret;

    /* nothing can be cached before the first Windows vCPU entered (the executor only touches the system page,
     * whose descriptors never change) */
    if (!atomic_load( &any_entered )) return 0;

    start = mach_absolute_time();
    if ((ret = tlbi_initiator( va, count, all )) <= 0)
    {
        if (!ret)
        {
            tlbi_initiator_count++;
            tlbi_initiator_ticks += mach_absolute_time() - start;
        }
        return ret;
    }

    pthread_mutex_lock( &tlbi_mutex );
    if (all || count > MAILBOX_MAX_VA) mailbox[0] = 0;
    else
    {
        memcpy( mailbox + 1, va, count * sizeof(*va) );
        mailbox[0] = count;
    }
    req = ++tlbi_req;
    pthread_cond_broadcast( &tlbi_cond );
    while (tlbi_done != req) pthread_cond_wait( &tlbi_cond, &tlbi_mutex );
    ret = tlbi_status;
    tlbi_count++;
    tlbi_ticks += mach_absolute_time() - start;
    pthread_mutex_unlock( &tlbi_mutex );
    return ret;
}


/***********************************************************************
 *           create_thread_no_signals
 *
 * Helper threads (the vel1 kicker, the TLBI executor) must never take Wine's signals: create them with
 * everything blocked, which they inherit.
 */
static void block_all_signals( sigset_t *old )
{
    sigset_t all;
    sigfillset( &all );
    pthread_sigmask( SIG_BLOCK, &all, old );
}


/***********************************************************************
 *           init_sys_page
 */
static void init_sys_page(void)
{
    static const uint8_t s1[4] = { GMM_S1_RX, GMM_S1_RX, GMM_S1_RW, GMM_S1_NONE };
    size_t stub_size = vcpu_tlbi_stub_end - vcpu_tlbi_stub_start;
    int ret;

    sys_page = mmap( NULL, SYS_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, VM_MAKE_TAG(250), 0 );
    if (sys_page == MAP_FAILED) vcpu_fatal( "system page mmap failed\n" );
    /* guest memory is never shared with a fork() child (virtual.c: anon_mmap_fixed_tag) */
    if (minherit( sys_page, SYS_PAGE_SIZE, VM_INHERIT_NONE )) vcpu_fatal( "system page minherit failed\n" );
    if ((ret = vel1_blob_install( sys_page + SYS_BLOB_OFF, 0x1000 ))) vcpu_fatal( "vel1_blob_install: %d\n", ret );
    memcpy( sys_page + SYS_TLBI_OFF, vcpu_tlbi_stub_start, stub_size );
    sys_icache_invalidate( sys_page + SYS_TLBI_OFF, stub_size );
    stub_size = vcpu_probe_stub_end - vcpu_probe_stub_start;
    memcpy( sys_page + SYS_PROBE_OFF, vcpu_probe_stub_start, stub_size );
    sys_icache_invalidate( sys_page + SYS_PROBE_OFF, stub_size );

    if ((ret = gmm_view_map( gmm, (uint64_t)sys_page, SYS_PAGE_SIZE, sys_page, GMM_S1_NONE )))
        vcpu_fatal( "gmm_view_map(system page %p): %d\n", sys_page, ret );
    if ((ret = gmm_vm_range_set_pages( gmm, (uint64_t)sys_page, 4, s1 )))
        vcpu_fatal( "gmm_vm_range_set_pages(system page): %d\n", ret );
}


/***********************************************************************
 *           init_kuser
 *
 * KUSER_SHARED_DATA lives at 0x7ffe0000, below the 4 GiB PAGEZERO where the host cannot map anything. It becomes a
 * gmm low-4GiB page (gmm owns its backing); the unix side keeps using its own host copy through user_shared_data
 * and virtual.c republishes it here.
 */
static void init_kuser(void)
{
    int ret;

    if ((ret = gmm_reserve( gmm, VCPU_KUSER_VA, 0x10000, GMM_RESERVE_LOW4G )))
        vcpu_fatal( "gmm_reserve(KUSER): %d\n", ret );
    if ((ret = gmm_commit( gmm, VCPU_KUSER_VA, 0x1000, GMM_PAGE_READONLY )))
        vcpu_fatal( "gmm_commit(KUSER): %d\n", ret );
    if (!(kuser_host = gmm_host_ptr( gmm, VCPU_KUSER_VA ))) vcpu_fatal( "no host pointer for KUSER\n" );
}


/***********************************************************************
 *           vcpu_selftest
 *
 * PMW_VCPU=selftest: bring everything up, then prove a vCPU can run guest code through gmm's tables without any
 * PE code: one executor round trip (a real TLBI) and one stub run on this thread. Exits the process.
 */
static vel1_vcpu selftest_vcpu;  /* the main thread's, kept for vcpu_selftest_probe */

static void vcpu_selftest(void)
{
    uint64_t *mailbox = (uint64_t *)(sys_page + SYS_MAILBOX_OFF);
    vel1_vcpu *v = &selftest_vcpu;
    vel1_vcpu_cfg cfg;
    uint64_t start, va = (uint64_t)sys_page + SYS_MAILBOX_OFF;
    int ret;

    atomic_store( &any_entered, 1 );
    start = mach_absolute_time();
    ret = tlbi_sync( NULL, &va, 1, 0 );
    fprintf( stderr, "vcpu selftest: executor TLBI (1 VA): %s, %.1f us\n", ret ? "FAIL" : "ok",
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );
    start = mach_absolute_time();
    ret = tlbi_sync( NULL, NULL, 0, 1 );
    fprintf( stderr, "vcpu selftest: executor TLBI (all): %s, %.1f us\n", ret ? "FAIL" : "ok",
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );

    memset( &cfg, 0, sizeof(cfg) );
    cfg.ttbr0 = gmm_ttbr0( gmm );
    cfg.blob_va = (uint64_t)sys_page + SYS_BLOB_OFF;
    cfg.pc = (uint64_t)sys_page + SYS_TLBI_OFF;
    cfg.x0 = va;
    cfg.hostcall_lo = (uint64_t)sys_page + SYS_TLBI_OFF;
    cfg.hostcall_hi = cfg.hostcall_lo + 0x1000;
    start = mach_absolute_time();
    if ((ret = vcpu_create( v, &cfg )))
    {
        fprintf( stderr, "vcpu selftest: vel1_vcpu_create FAIL %d (hv %#x)\n", ret, v->last_hv_err );
        exit( 1 );
    }
    fprintf( stderr, "vcpu selftest: vCPU create %.1f us\n", ticks_to_us( mach_absolute_time() - start ));
    mailbox[0] = 0;
    start = mach_absolute_time();
    ret = tlbi_run_once( v, va );
    fprintf( stderr, "vcpu selftest: guest stub on this thread: %s, %.1f us\n", ret ? "FAIL" : "ok",
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );
    /* the initiator forms (D18) on this vCPU, stopped at the stub's exit: the VA stub at blob +0x820 and the
     * whole-VMID entry at +0x890 */
    start = mach_absolute_time();
    ret = vel1_run_tlbi( v, &va, 1 );
    fprintf( stderr, "vcpu selftest: initiator TLBI (1 VA): %s (%d), %.1f us\n", ret ? "FAIL" : "ok", ret,
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );
    start = mach_absolute_time();
    ret = vel1_run_tlbi_all( v );
    fprintf( stderr, "vcpu selftest: initiator TLBI (all): %s (%d), %.1f us\n", ret ? "FAIL" : "ok", ret,
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );
    /* and the same two through the backend, which now picks the executor (this thread has no vcpu_thread) */
    start = mach_absolute_time();
    ret = tlbi_sync( NULL, &va, 1, 0 );
    fprintf( stderr, "vcpu selftest: backend TLBI after the initiator forms: %s, %.1f us\n", ret ? "FAIL" : "ok",
             ticks_to_us( mach_absolute_time() - start ));
    if (ret) exit( 1 );
    /* vCPUs belong to their creating thread, and on macOS the Windows main thread (where the memory selftest runs)
     * is not this one (loader.c: apple_wine_thread): give this one back, the probe makes its own */
    if ((ret = vel1_vcpu_destroy( v ))) fprintf( stderr, "vcpu selftest: vel1_vcpu_destroy %d\n", ret );
    fprintf( stderr, "vcpu selftest: hardware PASS (VM %d-bit IPA, hardware TSO %s, sys page %p, KUSER host %p, "
             "ttbr0 %#llx)\n", VCPU_IPA_BITS, atomic_load( &tso_state ) > 0 ? "yes" : "NO", sys_page, kuser_host,
             (unsigned long long)gmm_ttbr0( gmm ));
    /* virtual_init continues with the memory selftest (virtual.c) */
}

/***********************************************************************
 *           vcpu_selftest_probe
 *
 * Selftest only: on the main thread's vCPU, read *va into *old and write value to it. Returns the exit kind:
 * VEL1_EXIT_HOSTCALL when both accesses were allowed, else the fault (in *e).
 */
vel1_exit_kind vcpu_selftest_probe( uint64_t va, uint64_t value, uint64_t *old, vel1_exit *e )
{
    vel1_vcpu *v = &selftest_vcpu;
    vel1_regs regs;
    vel1_exit_kind kind;
    int ret;

    memset( e, 0, sizeof(*e) );
    if (!atomic_load( &v->live ))  /* first probe: a vCPU on this (the calling) thread */
    {
        vel1_vcpu_cfg cfg;

        memset( &cfg, 0, sizeof(cfg) );
        cfg.ttbr0 = gmm_ttbr0( gmm );
        cfg.blob_va = (uint64_t)sys_page + SYS_BLOB_OFF;
        cfg.pc = (uint64_t)sys_page + SYS_PROBE_OFF;
        cfg.hostcall_lo = (uint64_t)sys_page + SYS_TLBI_OFF;
        cfg.hostcall_hi = cfg.hostcall_lo + 0x1000;
        if ((ret = vcpu_create( v, &cfg )))
        {
            fprintf( stderr, "vcpu selftest: probe vCPU create failed %d (hv %#x)\n", ret, v->last_hv_err );
            return VEL1_EXIT_ERROR;
        }
    }
    memset( &regs, 0, sizeof(regs) );
    regs.x[0] = va;
    regs.x[1] = value;
    regs.x[3] = 0xdeadbeefdeadbeefull;
    if ((ret = vel1_resume_at( v, (uint64_t)sys_page + SYS_PROBE_OFF, 0 )) ||
        (ret = vel1_regs_set( v, &regs, VEL1_R_X(0) | VEL1_R_X(1) | VEL1_R_X(3), 0 )))
    {
        fprintf( stderr, "vcpu selftest: probe setup failed %d (hv %#x)\n", ret, v->last_hv_err );
        return VEL1_EXIT_ERROR;
    }
    kind = vel1_run( v, e );
    if (kind == VEL1_EXIT_ERROR)
        fprintf( stderr, "vcpu selftest: probe vel1_run error %d (hv %#x)\n", e->err, e->hv_err );
    if (kind == VEL1_EXIT_HOSTCALL && e->hvc_imm != VCPU_HVC_PROBE_DONE) return VEL1_EXIT_UNKNOWN;
    if (kind == VEL1_EXIT_HOSTCALL && old)
    {
        if (vel1_regs_get( v, &regs, VEL1_R_X(3), 0 )) return VEL1_EXIT_ERROR;
        *old = regs.x[3];
    }
    return kind;
}



/***********************************************************************
 * The per-thread loop
 *
 * One vCPU per Windows thread, created on the thread itself. struct syscall_frame stays the thread's user-mode
 * truth: each exit fills it (the same registers the asm dispatchers save), the exit is dispatched, and the frame
 * goes back into the vCPU (the same registers __wine_syscall_dispatcher_return restores).
 *
 * The in_syscall mark decides where a SIGUSR1/SIGQUIT goes (vcpu_el1.h D15): while it is clear the thread is in or
 * about to enter the guest, and the handler only kicks the vCPU (no hv_* call, D8); the loop then suspends from
 * the full vCPU state. While it is set, the frame is complete and the existing host path runs. Order: fill the
 * frame, set the mark, take any kick left pending; clear the mark before writing registers back into the vCPU, so
 * a context change made by a signal after that point is never lost (the kick makes vel1_run return at once).
 */
struct vcpu_level
{
    jmp_buf             resume;        /* handle_syscall_fault returns a syscall's status here */
    struct vcpu_level  *prev;
    vel1_exit_kind      kind;          /* SYSCALL or UNIX_CALL being dispatched */
    BOOL                done;          /* NtCallbackReturn ended this (nested) level */
    BOOL                dispatching;   /* inside the syscall / unix call itself: the only place resume is valid */
    BOOL                callback_ran;  /* a nested callback ran other guest code on the vCPU */
    void               *cb_ret_ptr;
    ULONG               cb_ret_len;
    NTSTATUS            cb_status;
};

/***********************************************************************
 * PMW_VCPU_PROF=<seconds>: where the vCPU threads' time goes
 *
 * Every <seconds>, one [VCPU-PROF] block on stderr with the interval's deltas: time inside vel1_run (the guest:
 * translated x86 code, FEX's JIT, native ARM64EC code, all together), and host time after each exit until the next
 * entry, charged to the exit that caused it (per syscall, by name where the table has names; unix calls; faults;
 * kicks), plus the whole process's CPU time, which also covers threads that never run guest code (the driver's
 * compile threads, the KUSER publisher). Waits are host time too: a parked NtWaitForSingleObject shows as its
 * wall time. Host-side clock reads only (CNTVCT_EL0, ~1 ns); no hv_* call is added.
 */
struct prof_bucket
{
    _Atomic uint64_t count, ticks;
};

#define PROF_KINDS VEL1_EXIT__COUNT

unsigned int vcpu_prof_interval;
#define prof_interval vcpu_prof_interval
static struct prof_bucket prof_guest;
static struct prof_bucket prof_kind[PROF_KINDS];
static struct prof_bucket prof_sys[2][4096];
static struct prof_bucket prof_extra[VCPU_PROF_IDS];
/* live Windows-thread vCPUs and their high-water mark: HVF allows 64 vCPUs per VM (one is the TLB executor's), so
 * a process past 63 threads cannot run in this 1:1 mode; the peak is what an M:N pool has to absorb */
static _Atomic int prof_vcpus_live, prof_vcpus_peak;

/* M:N sizing (release-on-block): how long blocking waits last, from the wait syscall's exit to the guest entry that
 * returns from it (user callbacks inside it are counted, not split out), how many threads sit in one at once, how
 * many threads had a long one, and how many user callbacks each wait makes (each would re-acquire a released vCPU).
 * Only the outermost wait of a thread is followed; a wait inside one of its callbacks is not. */
#define PROF_LONG_WAIT_US 4000
static const unsigned int prof_hist_us[] = { 16, 128, 1000, 4000, 16000, 100000, 1000000 };
#define PROF_HIST_N (ARRAY_SIZE(prof_hist_us) + 1)
enum { PROF_HIST_WAIT, PROF_HIST_UNIX, PROF_HISTS };
static struct prof_bucket prof_hist[PROF_HISTS][PROF_HIST_N];
static _Atomic int prof_parked, prof_parked_peak, prof_long_threads;
static _Atomic unsigned int prof_epoch = 1;
static _Atomic uint64_t prof_wait_cbs, prof_waits_with_cbs;
static signed char prof_wait_class[2][4096];  /* 0 not looked up yet, 1 blocking wait, -1 not */
static double prof_ticks_per_us = 1;

static const char * const prof_extra_names[VCPU_PROF_IDS] =
{
    "in:s1 sync", "in:s1 revoke", "in:icache sync", "in:tlbi", "in:gmm_vm_fault", "lock:virtual_mutex",
    "fault:retry", "fault:handled", "fault:raised", "in:hv_vm_map", "in:hv_vm_unmap",
};

/* unix calls by (function table, index): a slot is filled once under prof_unix_mutex, then published by ready */
#define PROF_UNIX_SLOTS 2048
static struct
{
    const void *table;
    uint64_t    code;
    atomic_int  ready;
} prof_unix_key[PROF_UNIX_SLOTS];
static struct prof_bucket prof_unix[PROF_UNIX_SLOTS];
static pthread_mutex_t prof_unix_mutex = PTHREAD_MUTEX_INITIALIZER;


extern const char *ntdll_syscall_name( UINT id );

#define prof_now vcpu_prof_now

static inline void prof_add( struct prof_bucket *b, uint64_t ticks )
{
    atomic_fetch_add_explicit( &b->count, 1, memory_order_relaxed );
    atomic_fetch_add_explicit( &b->ticks, ticks, memory_order_relaxed );
}

void vcpu_prof_add( enum vcpu_prof_id id, uint64_t ticks )
{
    prof_add( &prof_extra[id], ticks );
}

static struct prof_bucket *prof_unix_bucket( const void *table, uint64_t code )
{
    unsigned int i, h0 = (unsigned int)((((uintptr_t)table >> 4) * 0x9e3779b1u) ^ (code * 0x85ebca6bu)) % PROF_UNIX_SLOTS;
    unsigned int h = h0;

    for (i = 0; i < PROF_UNIX_SLOTS; i++, h = (h + 1) % PROF_UNIX_SLOTS)
    {
        if (!atomic_load_explicit( &prof_unix_key[h].ready, memory_order_acquire )) break;
        if (prof_unix_key[h].table == table && prof_unix_key[h].code == code) return &prof_unix[h];
    }
    /* first sighting: insert under the mutex (a racing insert of the same key is found by the rescan) */
    pthread_mutex_lock( &prof_unix_mutex );
    for (i = 0, h = h0; i < PROF_UNIX_SLOTS; i++, h = (h + 1) % PROF_UNIX_SLOTS)
    {
        if (!atomic_load_explicit( &prof_unix_key[h].ready, memory_order_acquire ))
        {
            prof_unix_key[h].table = table;
            prof_unix_key[h].code = code;
            atomic_store_explicit( &prof_unix_key[h].ready, 1, memory_order_release );
            break;
        }
        if (prof_unix_key[h].table == table && prof_unix_key[h].code == code) break;
    }
    pthread_mutex_unlock( &prof_unix_mutex );
    return i < PROF_UNIX_SLOTS ? &prof_unix[h] : &prof_kind[VEL1_EXIT_UNIX_CALL];
}

static struct prof_bucket *prof_sys_bucket( UINT id )
{
    UINT idx = (id >> 12) & 3;
    return idx < 2 ? &prof_sys[idx][id & 0xfff] : &prof_kind[VEL1_EXIT_SYSCALL];
}

struct prof_row
{
    const char *name;                   /* NULL: buf (rows are sorted, so never point into one) */
    char        buf[24];
    uint64_t    count, ticks;
};

static int prof_row_cmp( const void *a, const void *b )
{
    const struct prof_row *x = a, *y = b;
    return x->ticks < y->ticks ? 1 : x->ticks > y->ticks ? -1 : 0;
}

static BOOL prof_is_wait( const char *name )
{
    static const char * const waits[] = { "NtWaitFor", "NtRemoveIoCompletion", "NtDelayExecution",
                                          "NtSignalAndWait", "NtYieldExecution", "NtUserMsgWaitForMultipleObjectsEx",
                                          "NtReplyWaitReceivePort", "NtWaitForAlertByThreadId" };
    unsigned int i;

    for (i = 0; name && i < ARRAY_SIZE(waits); i++)
        if (!strncmp( name, waits[i], strlen( waits[i] ))) return TRUE;
    return name && (!strcmp( name, "NtUserGetMessage" ) || !strcmp( name, "NtUserWaitMessage" ));
}

/* a syscall that can park its thread (NtYieldExecution cannot); looked up once per id */
static BOOL prof_sys_blocks( UINT id )
{
    UINT idx = (id >> 12) & 3;
    signed char *class;
    const char *name;

    if (idx >= 2) return FALSE;
    class = &prof_wait_class[idx][id & 0xfff];
    if (!*class)
    {
        name = ntdll_syscall_name( id );
        *class = prof_is_wait( name ) && strcmp( name, "NtYieldExecution" ) ? 1 : -1;
    }
    return *class > 0;
}

static void prof_hist_add( unsigned int hist, uint64_t ticks, double ticks_per_us )
{
    unsigned int i, us = ticks / ticks_per_us;

    for (i = 0; i < ARRAY_SIZE(prof_hist_us) && us >= prof_hist_us[i]; i++) ;
    prof_add( &prof_hist[hist][i], ticks );
}

static void prof_hist_print( const char *what, unsigned int hist, double hz )
{
    static uint64_t last_count[PROF_HISTS][PROF_HIST_N], last_ticks[PROF_HISTS][PROF_HIST_N];
    char line[512];
    unsigned int i;
    uint64_t total = 0;
    int len = 0;

    for (i = 0; i < PROF_HIST_N; i++)
    {
        uint64_t c = atomic_load_explicit( &prof_hist[hist][i].count, memory_order_relaxed );
        uint64_t t = atomic_load_explicit( &prof_hist[hist][i].ticks, memory_order_relaxed );
        uint64_t dc = c - last_count[hist][i], dt = t - last_ticks[hist][i];

        last_count[hist][i] = c;
        last_ticks[hist][i] = t;
        total += dc;
        if (len >= sizeof(line) - 48) continue;
        if (i < ARRAY_SIZE(prof_hist_us))
            len += snprintf( line + len, sizeof(line) - len, " <%u%s", prof_hist_us[i] >= 1000 ? prof_hist_us[i] / 1000
                             : prof_hist_us[i], prof_hist_us[i] >= 1000 ? "ms" : "us" );
        else
            len += snprintf( line + len, sizeof(line) - len, " >=1s" );
        len += snprintf( line + len, sizeof(line) - len, " %llu (%.2fs)", (unsigned long long)dc, dt / hz );
    }
    if (total) fprintf( stderr, "[VCPU-PROF] pid %d   %s by length:%s\n", (int)getpid(), what, line );
}

static void *prof_thread( void *arg )
{
    enum { NSYS = 2 * 4096, NUNIX0 = NSYS + PROF_KINDS + VCPU_PROF_IDS, NROWS = NUNIX0 + PROF_UNIX_SLOTS };
    static uint64_t last_count[NROWS + 1], last_ticks[NROWS + 1];
    static struct prof_row rows[NROWS];
    uint64_t freq, start = prof_now(), last_cpu = 0;
    double hz;

    __asm__ volatile( "mrs %0, cntfrq_el0" : "=r" (freq) );
    hz = freq;
    for (;;)
    {
        struct rusage ru;
        uint64_t cpu, guest_c, guest_t, host = 0, wait = 0;
        unsigned int i, n = 0;

        sleep( prof_interval );
        getrusage( RUSAGE_SELF, &ru );
        cpu = (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000ull + ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;

        for (i = 0; i < NROWS; i++)
        {
            struct prof_bucket *b = i < NSYS ? &prof_sys[i / 4096][i % 4096]
                                    : i < NSYS + PROF_KINDS ? &prof_kind[i - NSYS]
                                    : i < NUNIX0 ? &prof_extra[i - NSYS - PROF_KINDS] : &prof_unix[i - NUNIX0];
            uint64_t c = atomic_load_explicit( &b->count, memory_order_relaxed );
            uint64_t t = atomic_load_explicit( &b->ticks, memory_order_relaxed );
            struct prof_row *r = &rows[n];

            r->count = c - last_count[i];
            r->ticks = t - last_ticks[i];
            last_count[i] = c;
            last_ticks[i] = t;
            if (!r->count) continue;
            if (i < NSYS)
            {
                UINT id = ((i / 4096) << 12) | (i % 4096);
                if (!(r->name = ntdll_syscall_name( id )) || !r->name[0])
                {
                    r->name = NULL;
                    snprintf( r->buf, sizeof(r->buf), "syscall %04x", id );
                }
                if (prof_is_wait( r->name )) wait += r->ticks;
            }
            else if (i >= NUNIX0)
            {
                Dl_info info;
                const char *mod = "?", *slash;

                if (dladdr( prof_unix_key[i - NUNIX0].table, &info ) && info.dli_fname)
                    mod = (slash = strrchr( info.dli_fname, '/' )) ? slash + 1 : info.dli_fname;
                snprintf( r->buf, sizeof(r->buf), "unix:%.14s#%llu", mod,
                          (unsigned long long)prof_unix_key[i - NUNIX0].code );
                r->name = NULL;
            }
            else if (i >= NSYS + PROF_KINDS)
            {
                r->name = prof_extra_names[i - NSYS - PROF_KINDS];
                /* nested in (or, for faults, replacing) what the rows above charge: not added to host */
                if (i - NSYS - PROF_KINDS < VCPU_PROF_FAULT_RETRY) { n++; continue; }
            }
            else
            {
                snprintf( r->buf, sizeof(r->buf), "exit:%s", vel1_exit_kind_name( i - NSYS ));
                r->name = NULL;
            }
            host += r->ticks;
            n++;
        }
        guest_c = atomic_load_explicit( &prof_guest.count, memory_order_relaxed );
        guest_t = atomic_load_explicit( &prof_guest.ticks, memory_order_relaxed );
        qsort( rows, n, sizeof(rows[0]), prof_row_cmp );

        fprintf( stderr, "[VCPU-PROF] pid %d t=%.1f s: vCPUs %d (peak %d) | guest %.3f s (%llu entries) | host after exits "
                 "%.3f s, of it waits %.3f s | process CPU %.3f s over %u s\n", (int)getpid(), (prof_now() - start) / hz,
                 atomic_load( &prof_vcpus_live ), atomic_load( &prof_vcpus_peak ),
                 (guest_t - last_ticks[NROWS]) / hz, (unsigned long long)(guest_c - last_count[NROWS]),
                 host / hz, wait / hz, (cpu - last_cpu) / 1e6, prof_interval );
        if (vcpu_mn)
        {
            char line[256];
            vcpu_pool_line( line, sizeof(line) );
            fprintf( stderr, "[VCPU-PROF] pid %d %s\n", (int)getpid(), line );
        }
        for (i = 0; i < n && i < 24; i++)
            fprintf( stderr, "[VCPU-PROF] pid %d   %-34s %9llu calls %8.3f s  %8.2f us avg%s\n",
                     (int)getpid(), rows[i].name ? rows[i].name : rows[i].buf,
                     (unsigned long long)rows[i].count, rows[i].ticks / hz, rows[i].ticks / hz * 1e6 / rows[i].count,
                     prof_is_wait( rows[i].name ) ? "  (wait)" : "" );
        {
            static uint64_t last_cbs, last_with;
            uint64_t cbs = atomic_load( &prof_wait_cbs ), with = atomic_load( &prof_waits_with_cbs );
            int parked = atomic_load( &prof_parked );

            prof_hist_print( "blocking waits", PROF_HIST_WAIT, hz );
            prof_hist_print( "unix calls", PROF_HIST_UNIX, hz );
            fprintf( stderr, "[VCPU-PROF] pid %d   parked in a wait now %d (peak %d) | threads with a wait >= %u ms: %d "
                     "| user callbacks inside waits %llu (from %llu waits)\n", (int)getpid(), parked,
                     atomic_exchange( &prof_parked_peak, parked ), PROF_LONG_WAIT_US / 1000,
                     atomic_exchange( &prof_long_threads, 0 ), (unsigned long long)(cbs - last_cbs),
                     (unsigned long long)(with - last_with) );
            atomic_fetch_add( &prof_epoch, 1 );
            last_cbs = cbs;
            last_with = with;
        }
        {
            /* gmm's thin mutator by phase (vcpu_gmm_arm64.c builds it with GMM_PROFILE); the view path is not split */
            static const char * const names[GMM_PROF_N] = { "args", "plan", "pt", "guard", "ipa", "urecs", "reserve",
                                                            "s2map", "insert", "desc", "tlbi", "unmap", "free", "trace" };
            static uint64_t last_gmm[GMM_PROF_N];
            uint64_t now_gmm[GMM_PROF_N], total = 0;
            char line[512];
            int len = 0;

            gmm_debug_prof_get( now_gmm );
            for (i = 0; i < GMM_PROF_N; i++) if (i != GMM_PROF_TRACE) total += now_gmm[i] - last_gmm[i];
            if (total)
            {
                for (i = 0; i < GMM_PROF_N && len < sizeof(line) - 32; i++)
                    if (now_gmm[i] - last_gmm[i] >= 1000000)
                        len += snprintf( line + len, sizeof(line) - len, " %s %.0f", names[i],
                                         (now_gmm[i] - last_gmm[i]) / 1e6 );
                fprintf( stderr, "[VCPU-PROF] pid %d   gmm thin phases (ms): total %.0f |%s\n", (int)getpid(),
                         total / 1e6, line );
            }
            memcpy( last_gmm, now_gmm, sizeof(last_gmm) );
        }
        last_count[NROWS] = guest_c;
        last_ticks[NROWS] = guest_t;
        last_cpu = cpu;
    }
    return NULL;
}

static void prof_start(void)
{
    const char *env = getenv( "PMW_VCPU_PROF" );
    pthread_t thread;
    sigset_t old;

    if (!env || (prof_interval = atoi( env )) <= 0)
    {
        prof_interval = 0;
        return;
    }
    {
        uint64_t freq;
        __asm__ volatile( "mrs %0, cntfrq_el0" : "=r" (freq) );
        prof_ticks_per_us = freq / 1e6;
    }
    block_all_signals( &old );
    if (!pthread_create( &thread, NULL, prof_thread, NULL )) pthread_detach( thread );
    else prof_interval = 0;
    pthread_sigmask( SIG_SETMASK, &old, NULL );
}

struct vcpu_thread
{
    vel1_vcpu           vcpu;          /* host-only memory (D12); the thread finds it through vcpu_key */
    atomic_int          in_syscall;
    atomic_int          quit;
    volatile sig_atomic_t hv_depth;    /* inside a vel1 call: never destroy the vCPU from a handler then */
    struct vcpu_level  *level;
    uint64_t            exits, syscalls, unix_calls, faults, kicks, kick_failures;
    uint64_t            unknown_exits; /* HV_EXIT_REASON_UNKNOWN exits re-entered (see vcpu_run) */
    unsigned int        unknown_run;   /* ... of them in a row, with no other exit in between */
    vel1_pool_member    pool_member;   /* M:N: this thread's pool record; valid until vel1_pool_member_fini (R10) */
    vel1_ctx            ctx;           /* M:N: the guest context while the thread holds no vCPU */
    vel1_vcpu_cfg       cfg;           /* M:N: the create config, for every re-create (restore overwrites pc/sp) */
    BOOL                has_vcpu;      /* always TRUE without M:N */
    BOOL                stranded;      /* a vel1_vcpu_destroy failed: the slot is lost for good (D16) */
    BOOL                preempt;       /* vel1_pool_take_preempt said so; acted on at the next preempt point */
    BOOL                presenter;     /* __wine_vcpu_mark_presenter: EXEMPT, never released */
    int                 unblock_fd;    /* the write end of this thread's wait pipe (the monitor's pipe wake) */
    atomic_int          unblock_pending;  /* one unblock message in flight at most */
    atomic_int          block_kind;    /* VCPU_BLOCK_NONE / _PIPE / _FUTEX: how the monitor can wake the wait */
    const LONG *_Atomic block_word;    /* the futex word of a VCPU_BLOCK_FUTEX wait */
    uint64_t            block_start;   /* vel1_pool_now_ns() at the block point */
    unsigned int        block_depth;   /* nested block points (a suspend's server wait inside usr1_handler, inside a
                                          wait): only the outermost one is tracked */
    uint64_t            prof_mark;     /* PMW_VCPU_PROF: when the last exit came back to the host */
    struct prof_bucket *prof_charge;   /* PMW_VCPU_PROF: what the host time since then is spent on */
    BOOL                prof_unix;     /* PMW_VCPU_PROF: that is a unix call */
    uint64_t            wait_t0;       /* PMW_VCPU_PROF: the outermost blocking wait's exit, 0 if none */
    struct vcpu_level  *wait_level;    /* PMW_VCPU_PROF: the level it returns to */
    unsigned int        wait_cbs;      /* PMW_VCPU_PROF: user callbacks made inside it */
    unsigned int        long_epoch;    /* PMW_VCPU_PROF: the report interval this thread last counted a long wait in */
};

static pthread_key_t vcpu_key;


static void prof_wait_start( struct vcpu_thread *vt )
{
    int parked = atomic_fetch_add( &prof_parked, 1 ) + 1, peak = atomic_load( &prof_parked_peak );

    while (parked > peak && !atomic_compare_exchange_weak( &prof_parked_peak, &peak, parked )) ;
    vt->wait_t0 = vt->prof_mark;
    vt->wait_level = vt->level;
    vt->wait_cbs = 0;
}

static void prof_wait_end( struct vcpu_thread *vt, uint64_t now )
{
    unsigned int epoch = atomic_load( &prof_epoch );
    uint64_t ticks = now - vt->wait_t0;

    prof_hist_add( PROF_HIST_WAIT, ticks, prof_ticks_per_us );
    if (ticks >= PROF_LONG_WAIT_US * prof_ticks_per_us && vt->long_epoch != epoch)
    {
        vt->long_epoch = epoch;
        atomic_fetch_add( &prof_long_threads, 1 );
    }
    if (vt->wait_cbs)
    {
        atomic_fetch_add( &prof_wait_cbs, vt->wait_cbs );
        atomic_fetch_add( &prof_waits_with_cbs, 1 );
    }
    atomic_fetch_sub( &prof_parked, 1 );
    vt->wait_t0 = 0;
}

extern void trace_syscall( UINT id, ULONG_PTR *args, ULONG len );
extern void trace_sysret( UINT id, ULONG_PTR retval );

static inline struct vcpu_thread *vcpu_current(void)
{
    return pthread_getspecific( vcpu_key );
}

/***********************************************************************
 *           tlbi_initiator
 *
 * The initiator TLBI (vcpu_el1.h D18, openrosetta's G11): a Windows thread calling gmm from a syscall or a fault
 * has its own vCPU stopped at an exit, and that vCPU runs the shootdown itself (~1.2 us against the executor's
 * round trip). gmm is called from virtual.c's uninterrupted sections, so no host signal lands in the stub; a
 * kick's CANCELED is absorbed by vel1 and stays pending. Returns 0 done, -1 fatal (the vCPU is left unresumable,
 * and gmm aborts on a failed backend), 1 not usable here: a host-only thread, a handler that interrupted a vel1
 * call (hv_depth), a vCPU that is not live, VEL1_E_BUSY (state restored, shootdown not done), or a shape the stub
 * does not take; the caller uses the parked executor then.
 */
static int tlbi_initiator( const uint64_t *va, size_t count, int all )
{
    struct vcpu_thread *vt = vcpu_current();
    int ret;

    if (!vt || !vt->has_vcpu || vt->hv_depth || !(all || (count && count <= VEL1_TLBI_MAX_VA))) return 1;
    vt->hv_depth++;
    ret = all ? vel1_run_tlbi_all( &vt->vcpu ) : vel1_run_tlbi( &vt->vcpu, va, count );
    vt->hv_depth--;
    if (!ret) return 0;
    if (ret == VEL1_E_HV || ret == VEL1_E_STUB || ret == VEL1_E_ARG)
    {
        ERR( "initiator TLBI failed %d (hv %#x) on thread %04x\n", ret, vt->vcpu.last_hv_err,
             (UINT)GetCurrentThreadId() );
        return -1;
    }
    tlbi_initiator_refused++;  /* VEL1_E_BUSY, VEL1_E_STATE, VEL1_E_WRONG_THREAD */
    return 1;
}

/* What a signal handler would have blocked (its sa_mask) plus SIGQUIT: the loop does handler work (suspend, faults)
 * in normal context, and no SIGQUIT may end the thread inside HVF, gmm or vel1 bookkeeping. */
static void vcpu_block_signals( sigset_t *old )
{
    sigset_t set = server_block_set;

    sigaddset( &set, SIGQUIT );
    pthread_sigmask( SIG_BLOCK, &set, old );
}

static void vcpu_unblock_signals(void)
{
    sigset_t set = server_block_set;

    sigaddset( &set, SIGQUIT );
    pthread_sigmask( SIG_UNBLOCK, &set, NULL );
}

static void vcpu_dump_exit( const char *what, struct vcpu_thread *vt, const vel1_exit *e,
                            const struct syscall_frame *frame )
{
    unsigned int i;

    fprintf( stderr, "wine: vCPU mode: %s: exit %s err %d hv %#x reason %u esr %#llx far %#llx elr %#llx "
             "spsr %#llx pc %#llx fclass %s\n", what, vel1_exit_kind_name( e->kind ), e->err, e->hv_err,
             e->hv_reason, (unsigned long long)e->esr, (unsigned long long)e->far, (unsigned long long)e->elr,
             (unsigned long long)e->spsr, (unsigned long long)e->pc, vel1_fault_class_name( e->fclass ));
    if (frame)
    {
        for (i = 0; i < 29; i++)
            fprintf( stderr, " x%-2u=%016llx%s", i, (unsigned long long)frame->x[i], (i % 4) == 3 ? "\n" : "" );
        fprintf( stderr, " fp=%016llx lr=%016llx sp=%016llx pc=%016llx cpsr=%08x\n",
                 (unsigned long long)frame->fp, (unsigned long long)frame->lr, (unsigned long long)frame->sp,
                 (unsigned long long)frame->pc, (UINT)frame->cpsr );
    }
    if (vt)
        fprintf( stderr, " thread %04x: exits %llu syscalls %llu unix calls %llu faults %llu kicks %llu "
                 "(signal failures %llu)\n",
                 (UINT)GetCurrentThreadId(), (unsigned long long)vt->exits, (unsigned long long)vt->syscalls,
                 (unsigned long long)vt->unix_calls, (unsigned long long)vt->faults, (unsigned long long)vt->kicks,
                 (unsigned long long)vt->kick_failures );
}

static void DECLSPEC_NORETURN vcpu_fatal_exit( struct vcpu_thread *vt, const vel1_exit *e,
                                               const struct syscall_frame *frame )
{
    vcpu_dump_exit( "fatal exit", vt, e, frame );
    abort_process( 1 );
}

static void vcpu_pool_line( char *buf, size_t size )
{
    vel1_pool_stats st;

    vel1_pool_get_stats( &vcpu_pool, &st );
    snprintf( buf, size, "pool: free %u holders %u waiters %u | acquires %llu (waited %llu, %.1f ms total, max %.1f "
              "ms) | releases %llu (block %llu, preempt %llu) preempts %llu unblocks %llu | threads %d (peak %d)",
              st.free_now, st.holders_now, st.waiters_now, (unsigned long long)st.acquires,
              (unsigned long long)st.acquire_waits, st.total_wait_ns / 1e6, st.max_wait_ns / 1e6,
              (unsigned long long)st.releases, (unsigned long long)atomic_load( &prof_rel_block ),
              (unsigned long long)atomic_load( &prof_rel_preempt ), (unsigned long long)st.preempts,
              (unsigned long long)st.unblocks, atomic_load( &prof_threads_live ), atomic_load( &prof_threads_peak ));
}

/* wait for a slot. Every signal blocked: a thread killed while queued would leave a dead member in the FIFO */
static void vcpu_pool_acquire( struct vcpu_thread *vt )
{
    sigset_t old;
    int ret;

    block_all_signals( &old );
    ret = vel1_pool_acquire( &vcpu_pool, &vt->pool_member );
    pthread_sigmask( SIG_SETMASK, &old, NULL );
    if (ret) vcpu_fatal( "vel1_pool_acquire for thread %04x failed %d\n", (UINT)GetCurrentThreadId(), ret );
}

static void vcpu_note_vcpu_up(void)
{
    int live = atomic_fetch_add( &prof_vcpus_live, 1 ) + 1, peak = atomic_load( &prof_vcpus_peak );
    while (live > peak && !atomic_compare_exchange_weak( &prof_vcpus_peak, &peak, live )) ;
}

/* M:N: make sure the thread holds a vCPU before any vel1_* call on it (spec §5). Called with in_syscall set */
static void vcpu_ensure( struct vcpu_thread *vt )
{
    sigset_t old;
    int ret;

    if (vt->has_vcpu) return;
    vcpu_pool_acquire( vt );
    block_all_signals( &old );  /* nothing may interrupt the create and restore (HVF, vel1 locks) */
    ret = vcpu_create( &vt->vcpu, &vt->cfg );
    if (!ret) ret = vel1_ctx_restore( &vt->vcpu, &vt->ctx );
    if (ret)
    {
        char line[256];
        vcpu_pool_line( line, sizeof(line) );
        vcpu_fatal( "vCPU re-create for thread %04x failed %d (hv %#x); %s\n", (UINT)GetCurrentThreadId(), ret,
                    vt->vcpu.last_hv_err, line );
    }
    vt->has_vcpu = TRUE;
    vcpu_note_vcpu_up();
    pthread_sigmask( SIG_SETMASK, &old, NULL );
}

/* M:N: give the vCPU and the slot back, the context into vt->ctx. The caller blocks signals. Destroy before release,
 * always: the other order would let a waiter create while this vCPU still exists. FALSE: nothing was released */
static BOOL vcpu_release( struct vcpu_thread *vt )
{
    int ret;

    if (!vt->has_vcpu || vt->hv_depth || vt->presenter) return FALSE;
    if (vel1_ctx_save( &vt->vcpu, &vt->ctx )) return FALSE;
    if ((ret = vel1_vcpu_destroy( &vt->vcpu )))
    {
        vt->stranded = TRUE;
        vcpu_fatal( "vel1_vcpu_destroy for thread %04x failed %d: its slot is lost (D16)\n",
                    (UINT)GetCurrentThreadId(), ret );
    }
    vt->has_vcpu = FALSE;
    atomic_fetch_sub( &prof_vcpus_live, 1 );
    vel1_pool_release( &vcpu_pool, &vt->pool_member );
    return TRUE;
}

/* the monitor's callbacks: under the pool lock, never block, never call the pool (R10) */
static void vcpu_pool_kick( vel1_pool_member *m, void *arg )
{
    struct vcpu_thread *vt = CONTAINING_RECORD( m, struct vcpu_thread, pool_member );
    vel1_kick_remote( &vt->vcpu );  /* victims are inside vel1_run; vel1 re-checks liveness under its own lock */
}

static void vcpu_pool_unblock( vel1_pool_member *m, void *arg )
{
    struct vcpu_thread *vt = CONTAINING_RECORD( m, struct vcpu_thread, pool_member );

    switch (atomic_load( &vt->block_kind ))
    {
    case VCPU_BLOCK_PIPE:
        if (!atomic_exchange( &vt->unblock_pending, 1 ))
        {
            struct wake_up_reply reply;

            memset( &reply, 0, sizeof(reply) );
            reply.cookie = VCPU_UNBLOCK_COOKIE;
            /* one message in flight at most: the pipe cannot fill, so this cannot block */
            if (write( vt->unblock_fd, &reply, sizeof(reply) ) != sizeof(reply)) atomic_store( &vt->unblock_pending, 0 );
        }
        break;
    case VCPU_BLOCK_FUTEX:
    {
        const LONG *word = atomic_load( &vt->block_word );
        if (word) vcpu_futex_wake_word( word );
        break;
    }
    default:
        break;  /* the thread just left its wait: a spurious unblock, allowed */
    }
}

static vel1_exit_kind vcpu_run( struct vcpu_thread *vt, vel1_exit *e )
{
    vel1_exit_kind kind;

    for (;;)
    {
        uint64_t t0 = 0;

        if (prof_interval)
        {
            t0 = prof_now();
            if (vt->prof_charge) prof_add( vt->prof_charge, t0 - vt->prof_mark );
            if (vt->prof_unix) prof_hist_add( PROF_HIST_UNIX, t0 - vt->prof_mark, prof_ticks_per_us );
            if (vt->wait_t0 && vt->level == vt->wait_level) prof_wait_end( vt, t0 );
        }
        if (vcpu_mn)
        {
            if (!vt->has_vcpu) vcpu_fatal( "thread %04x entered vcpu_run without a vCPU\n", (UINT)GetCurrentThreadId() );
            vel1_pool_note_run_begin( &vt->pool_member, vel1_pool_now_ns() );
        }
        vt->hv_depth++;
        kind = vel1_run( &vt->vcpu, e );
        vt->hv_depth--;
        if (vcpu_mn)
        {
            vel1_pool_note_run_end( &vt->pool_member );
            /* R9: record after every return, whatever the exit; acted on at the next preempt point */
            if (vel1_pool_take_preempt( &vt->pool_member )) vt->preempt = TRUE;
        }
        vt->exits++;
        if (prof_interval)
        {
            vt->prof_mark = prof_now();
            prof_add( &prof_guest, vt->prof_mark - t0 );
            vt->prof_charge = &prof_kind[(unsigned int)kind < PROF_KINDS ? kind : 0];
            vt->prof_unix = FALSE;
        }
        if (kind != VEL1_EXIT_CANCELED) return kind;  /* past vel1's spurious bound: just go again */
    }
}

/***********************************************************************
 *           vcpu_emulation_entry
 *
 * ARM64EC: the frame resumes into x86 code (NtContinue / NtSetContextThread put an emulated pc into it and
 * set_context set RESTORE_FLAGS_EMULATION). As usr2_handler does on the EL0 path, the emulator gets the frame as a
 * CONTEXT on the target stack and control goes to KiUserEmulationDispatcher with sp at that context; every other
 * register comes from the frame. The caller stores *entry in full.
 */
static void vcpu_emulation_entry( const struct syscall_frame *frame, struct syscall_frame *entry )
{
    CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

    if (frame != get_syscall_frame() || !pKiUserEmulationDispatcher || !NtCurrentTeb()->ChpeV2CpuAreaInfo)
    {
        fprintf( stderr, "wine: vCPU mode: emulation entry from an unexpected frame %p (current %p, dispatcher %p)\n",
                 frame, get_syscall_frame(), pKiUserEmulationDispatcher );
        abort_process( 1 );
    }
    NtCurrentTeb()->ChpeV2CpuAreaInfo->InSimulation = 1;
    user_context->ContextFlags = CONTEXT_FULL;
    NtGetContextThread( GetCurrentThread(), user_context );
    *entry = *frame;
    entry->sp = (ULONG64)user_context;
    entry->pc = (ULONG64)pKiUserEmulationDispatcher;
    entry->restore_flags = 0;
    TRACE( "emulation entry: x86 pc %#llx, context %p\n", (unsigned long long)frame->pc, user_context );
}

/* M:N: act on a recorded preemption once the exit is fully handled, before the thread re-enters the guest and while
 * in_syscall is still set (spec §7): give the slot to the waiter and queue again at the back of the FIFO */
static void vcpu_preempt_point( struct vcpu_thread *vt )
{
    sigset_t old;

    if (!vcpu_mn || !vt->preempt) return;
    vt->preempt = FALSE;
    if (vt->presenter) return;  /* EXEMPT set after the pick: the pool does not retract it (R10) */
    block_all_signals( &old );
    if (vcpu_release( vt )) atomic_fetch_add( &prof_rel_preempt, 1 );
    pthread_sigmask( SIG_SETMASK, &old, NULL );
}

/* SIGUSR1 blocked: maybe inside a signal handler (our suspend waits in the server from usr1_handler). No pool call
 * that can release, and no note_wait, from there (R10 and the SIGUSR1 limit) */
static BOOL vcpu_in_handler_mask(void)
{
    sigset_t cur;

    pthread_sigmask( SIG_BLOCK, NULL, &cur );
    return sigismember( &cur, SIGUSR1 );
}

/* at a block point: release under the pool's policy, or mark the slot as held across the wait (R15) */
static void vcpu_block_decide( struct vcpu_thread *vt )
{
    sigset_t old;
    BOOL released = FALSE;

    if (!vt->has_vcpu) return;
    /* spec §5: release only while in_syscall is 1 (signal handlers then take the frame path, which needs no vCPU) */
    if (atomic_load( &vt->in_syscall ) && !vcpu_in_handler_mask() && !vt->hv_depth && !vt->presenter &&
        vel1_pool_should_release( &vcpu_pool, &vt->pool_member ))
    {
        block_all_signals( &old );
        released = vcpu_release( vt );
        pthread_sigmask( SIG_SETMASK, &old, NULL );
        if (released) atomic_fetch_add( &prof_rel_block, 1 );
    }
    if (!released) vel1_pool_note_block_begin( &vt->pool_member, vel1_pool_now_ns() );
}

BOOL vcpu_block_begin( int kind, const LONG *word )
{
    struct vcpu_thread *vt;

    if (!vcpu_mn || !(vt = vcpu_current())) return FALSE;
    if (vt->block_depth++) return FALSE;  /* nested (a signal handler's wait inside a wait): the outer one tracks */
    vt->block_start = vel1_pool_now_ns();
    atomic_store( &vt->block_word, word );
    atomic_store( &vt->block_kind, kind );
    vcpu_block_decide( vt );
    return TRUE;
}

void vcpu_block_end(void)
{
    struct vcpu_thread *vt;

    if (!vcpu_mn || !(vt = vcpu_current()) || !vt->block_depth) return;
    if (--vt->block_depth) return;  /* the end of a nested block point */
    atomic_store( &vt->block_kind, VCPU_BLOCK_NONE );
    atomic_store( &vt->block_word, NULL );
    vel1_pool_note_block_end( &vt->pool_member );
    if (!vcpu_in_handler_mask())
        vel1_pool_note_wait( &vcpu_pool, &vt->pool_member, vel1_pool_now_ns() - vt->block_start );
}

/* the wait was interrupted by the monitor's unblock: decide again (a waiter exists, so this releases) and wait on.
 * block_start and the wait average stay for the whole wait */
void vcpu_block_rearm(void)
{
    struct vcpu_thread *vt;

    if (!vcpu_mn || !(vt = vcpu_current())) return;
    atomic_store( &vt->unblock_pending, 0 );
    /* consumed by a nested wait (inside a signal handler): drop it; the monitor unblocks again after a quantum */
    if (vt->block_depth != 1 || vcpu_in_handler_mask()) return;
    vel1_pool_note_block_end( &vt->pool_member );
    vcpu_block_decide( vt );
}

/* write the whole frame into the vCPU and leave the syscall state (fault, kick, thread start) */
static void vcpu_store_full( struct vcpu_thread *vt, const struct syscall_frame *frame )
{
    struct syscall_frame entry;
    vel1_regs regs;
    int ret;

    if (vcpu_mn)
    {
        vcpu_preempt_point( vt );
        vcpu_ensure( vt );
    }
    /* signals held back during the fault / kick handling arrive now, with the mark set: they take the host path
     * and edit the frame, which is read below */
    vcpu_unblock_signals();
    atomic_store( &vt->in_syscall, 0 );
    atomic_signal_fence( memory_order_seq_cst );
    /* as usr2_handler: the flag asks for the slow path, the frame's pc decides (vcpu_return) */
    if ((frame->restore_flags & RESTORE_FLAGS_EMULATION) && is_emulated_code( frame->pc ))
    {
        TRACE( "emulation entry via store_full: restore_flags %#x pc %#llx sp %#llx lr %#llx\n",
               (UINT)frame->restore_flags, (unsigned long long)frame->pc, (unsigned long long)frame->sp,
               (unsigned long long)frame->lr );
        vcpu_emulation_entry( frame, &entry );
        frame = &entry;
    }
    vcpu_regs_from_frame( &regs, frame );
    vt->hv_depth++;
    ret = vel1_regs_set( &vt->vcpu, &regs, VCPU_FULL_CORE_MASK, VEL1_R_ALL_SIMD );
    vt->hv_depth--;
    if (ret)
    {
        fprintf( stderr, "wine: vCPU mode: vel1_regs_set(full) failed %d (pc %#llx)\n", ret,
                 (unsigned long long)frame->pc );
        abort_process( 1 );
    }
}

/* return from a syscall or unix call with ret, as __wine_syscall_dispatcher_return does */
static void vcpu_return( struct vcpu_thread *vt, struct vcpu_level *level, vel1_exit_kind kind, ULONG64 ret )
{
    struct syscall_frame *frame = get_syscall_frame();
    uint64_t core;
    uint32_t simd;
    vel1_regs regs;
    int err;

    if (vcpu_mn)
    {
        vcpu_preempt_point( vt );
        vcpu_ensure( vt );
    }
    atomic_store( &vt->in_syscall, 0 );
    atomic_signal_fence( memory_order_seq_cst );
    /* RESTORE_FLAGS_EMULATION only sends the EL0 return to the slow path (SIGUSR2); usr2_handler then enters the
     * emulator only if the frame's pc is still emulated code. It may not be: NtRaiseException's
     * call_user_exception_dispatcher sets the flag through NtSetContextThread (an x86 context from the emulator's
     * fault handler) and then points pc at the native KiUserExceptionDispatcher. Entering the emulator there ran
     * the dispatcher as an x64 call on a shifted stack (exception code 0, then "invalid frame"): STS2's exit crash. */
    if ((frame->restore_flags & RESTORE_FLAGS_EMULATION) && is_emulated_code( frame->pc ))
    {
        /* into x86 code: the emulator takes over with the frame as a CONTEXT, everything stored */
        struct syscall_frame entry;

        TRACE( "emulation entry via %s return: syscall %#x ret %#llx restore_flags %#x pc %#llx sp %#llx lr %#llx\n",
               kind == VEL1_EXIT_SYSCALL ? "syscall" : "unix call", (UINT)frame->syscall_id,
               (unsigned long long)ret, (UINT)frame->restore_flags, (unsigned long long)frame->pc,
               (unsigned long long)frame->sp, (unsigned long long)frame->lr );
        vcpu_emulation_entry( frame, &entry );
        vcpu_regs_from_frame( &regs, &entry );
        core = VCPU_FULL_CORE_MASK;
        simd = VEL1_R_ALL_SIMD;
    }
    else if (frame->restore_flags & RESTORE_FLAGS_EMULATION)
    {
        /* usr2_handler's native branch: the whole frame */
        vcpu_regs_from_frame( &regs, frame );
        core = VCPU_FULL_CORE_MASK;
        simd = VEL1_R_ALL_SIMD;
    }
    else if (!frame->restore_flags && !level->callback_ran) core = 0;  /* the fast path below */
    else vcpu_return_plan( frame, ret, level->callback_ran, &regs, &core, &simd );

    vt->hv_depth++;
    if (core) err = vel1_regs_set( &vt->vcpu, &regs, core, simd );
    /* the vCPU still holds everything else: only the stub's return is left to play */
    else if (kind == VEL1_EXIT_SYSCALL) err = vel1_syscall_return( &vt->vcpu, ret, frame->pc, frame->lr );
    else err = vel1_call_return( &vt->vcpu, ret, frame->pc );
    vt->hv_depth--;
    level->callback_ran = FALSE;
    if (err)
    {
        fprintf( stderr, "wine: vCPU mode: syscall return failed %d (pc %#llx)\n", err, (unsigned long long)frame->pc );
        abort_process( 1 );
    }
}

/* Apple-ABI shims per syscall table index: ntdll's own (vcpu_shims_arm64.c) serve table 0; other unix libraries
 * register theirs ({implementation, shim} pairs) with __wine_vcpu_add_syscall_shims, e.g. win32u for table 1. */
struct vcpu_shim_map
{
    const ULONG_PTR *service_table;     /* the ServiceTable this map was built for */
    const void      *target[];          /* per syscall number: the shim, or the implementation itself */
};

static pthread_mutex_t shim_map_mutex = PTHREAD_MUTEX_INITIALIZER;
static const void *const *registered_shims[4];  /* protected by shim_map_mutex */
static unsigned int registered_shim_count[4];   /* protected by shim_map_mutex */
static _Atomic(const struct vcpu_shim_map *) shim_maps[4];

/***********************************************************************
 *           __wine_vcpu_add_syscall_shims
 *
 * Register the Apple-ABI shims of syscall table 'index' (include/wine/unixlib.h). Drops the table's cached map so
 * the next syscall rebuilds it with them, should a syscall of that table already have been dispatched.
 */
void __wine_vcpu_add_syscall_shims( ULONG index, const void *const *pairs, unsigned int count )
{
    if (index >= ARRAY_SIZE(registered_shims)) return;
    pthread_mutex_lock( &shim_map_mutex );
    registered_shims[index] = pairs;
    registered_shim_count[index] = count;
    /* the old map is leaked: another thread may still be reading it */
    atomic_store_explicit( &shim_maps[index], NULL, memory_order_release );
    pthread_mutex_unlock( &shim_map_mutex );
}

/***********************************************************************
 *           __wine_vcpu_mark_presenter
 */
void __wine_vcpu_mark_presenter(void)
{
    struct vcpu_thread *vt;

    if (!vcpu_mn || !(vt = vcpu_current()) || vt->presenter) return;
    vt->presenter = TRUE;
    vel1_pool_add_flags( &vt->pool_member, VEL1_POOL_EXEMPT );  /* add_flags: set_flags would replace every flag */
}

/***********************************************************************
 *           __wine_user_shared_data
 *
 * The host's mapping of the KUSER_SHARED_DATA page (include/wine/unixlib.h): unix-side code in other libraries
 * must not read 0x7ffe0000, which the host cannot map (M1c: win32u's tick count reads faulted forever).
 */
const struct _KUSER_SHARED_DATA *__wine_user_shared_data(void)
{
    return user_shared_data;
}

/***********************************************************************
 *           __wine_vcpu_hardware_tso
 *
 * Whether this process's vCPUs run with hardware TSO (include/wine/unixlib.h). Decided by the process's first vCPU,
 * the TLB-shootdown executor created in vcpu_init_process, before any Windows code runs (vcpu_create).
 */
int __wine_vcpu_hardware_tso(void)
{
    return vcpu_mode && atomic_load( &tso_state ) > 0;
}

/***********************************************************************
 *           __wine_vcpu_active
 *
 * Whether Windows code runs in vCPUs in this process (include/wine/unixlib.h).
 */
int __wine_vcpu_active(void)
{
    return vcpu_mode != 0;
}

/***********************************************************************
 *           vcpu_syscall_target
 *
 * The function to call for a syscall: its Apple-ABI shim when it has one (ntdll's vcpu_shims_arm64.c for table
 * 0, the list registered with __wine_vcpu_add_syscall_shims for any table), else the implementation itself. Per
 * table, the map is built the first time the table is seen, and again if the table or its registration changes.
 */
static const void *vcpu_syscall_target( UINT table_index, const SYSTEM_SERVICE_TABLE *table, UINT num )
{
    const struct vcpu_shim_map *map = atomic_load_explicit( &shim_maps[table_index], memory_order_acquire );
    struct vcpu_shim_map *new_map;
    const void *const *pairs;
    unsigned int j, count;
    ULONG_PTR i;

    if (map && map->service_table == table->ServiceTable) return map->target[num];

    pthread_mutex_lock( &shim_map_mutex );
    map = atomic_load_explicit( &shim_maps[table_index], memory_order_relaxed );
    if (!map || map->service_table != table->ServiceTable)
    {
        if (!(new_map = calloc( 1, sizeof(*new_map) + table->ServiceLimit * sizeof(new_map->target[0]) )))
            vcpu_fatal( "out of memory for the shim map\n" );
        new_map->service_table = table->ServiceTable;
        pairs = registered_shims[table_index];
        count = registered_shim_count[table_index];
        for (i = 0; i < table->ServiceLimit; i++)
        {
            const void *func = (const void *)table->ServiceTable[i];

            new_map->target[i] = func;
            if (!table_index)
                for (j = 0; j < vcpu_syscall_shim_count; j++)
                    if (vcpu_syscall_shims[j].func == func) new_map->target[i] = vcpu_syscall_shims[j].shim;
            for (j = 0; j < count; j++)
                if (pairs[2 * j] == func) new_map->target[i] = pairs[2 * j + 1];
        }
        atomic_store_explicit( &shim_maps[table_index], new_map, memory_order_release );
        map = new_map;
    }
    pthread_mutex_unlock( &shim_map_mutex );
    return map->target[num];
}

static ULONG64 vcpu_dispatch_syscall( struct syscall_frame *frame, const vel1_exit *e )
{
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    UINT id = e->regs.x[8];
    SYSTEM_SERVICE_TABLE *table = thread_data->syscall_table + ((id >> 12) & 3);
    UINT num = id & 0xfff;
    ULONG64 args[32], ret;
    ULONG size, stack_bytes;
    void *func;

    if (num >= table->ServiceLimit) return STATUS_INVALID_SYSTEM_SERVICE;
    func = (void *)vcpu_syscall_target( (id >> 12) & 3, table, num );
    size = table->ArgumentTable[num];
    stack_bytes = size > 64 ? size - 64 : 0;
    if (stack_bytes && func == (void *)table->ServiceTable[num])
    {
        /* Windows put these in 8-byte slots; the Apple-ABI implementation would read them packed */
        fprintf( stderr, "wine: vCPU mode: syscall %#x has stack arguments but no Apple-ABI shim (re-run "
                 "proton-darwin mac/vcpu/gen/gen_syscall_shims.py: ntdll, win32u vcpu_shims_arm64.c)\n", id );
        abort_process( 1 );
    }
    memcpy( args, e->regs.x, 8 * sizeof(args[0]) );
    if (thread_data->syscall_trace)
    {
        memcpy( args + 8, (void *)frame->sp, min( stack_bytes, sizeof(args) - 64 ));
        trace_syscall( id, (ULONG_PTR *)args, size );
    }
    ret = vcpu_call_syscall( func, args, (const ULONG64 *)frame->sp, stack_bytes );
    if (thread_data->syscall_trace) trace_sysret( id, ret );
    return ret;
}

static void vcpu_handle_fault( struct vcpu_thread *vt, struct syscall_frame *frame, const vel1_exit *e )
{
    EXCEPTION_RECORD rec;
    ULONG64 pc_adjust;

    vt->faults++;
    if (prof_interval) vt->prof_charge = &prof_extra[VCPU_PROF_FAULT_RAISED];
    if (e->kind == VEL1_EXIT_FAULT_SYNC && (e->fclass == VEL1_FC_DATA_ABORT || e->fclass == VEL1_FC_INSN_ABORT))
    {
        uint64_t t0 = prof_interval ? prof_now() : 0;
        gmm_vfault_t vf = gmm_vm_fault( gmm, e->far, e->esr );

        if (prof_interval) vcpu_prof_add( VCPU_PROF_VM_FAULT, prof_now() - t0 );
        switch (vf)
        {
        case GMM_VF_RETRY:  /* a concurrent protection change already allows it */
            if (prof_interval)
            {
                static _Atomic uint64_t retries;
                uint64_t nr = atomic_fetch_add_explicit( &retries, 1, memory_order_relaxed );
                vt->prof_charge = &prof_extra[VCPU_PROF_FAULT_RETRY];
                if (!(nr & 0x3fff))
                    fprintf( stderr, "[VCPU-PROF] pid %d retry fault #%llu: %s far %#llx pc %#llx esr %#llx (dfsc %#x%s)\n",
                             (int)getpid(), (unsigned long long)nr, vel1_fault_class_name( e->fclass ),
                             (unsigned long long)e->far, (unsigned long long)frame->pc, (unsigned long long)e->esr,
                             (UINT)(e->esr & 0x3f), (e->esr >> 6) & 1 ? " write" : "" );
            }
            vcpu_store_full( vt, frame );
            return;
        case GMM_VF_FATAL:
            vcpu_fatal_exit( vt, e, frame );
        case GMM_VF_WINE:
            break;
        }
    }
    if (!vcpu_exit_to_exception( e, frame, &rec, &pc_adjust )) vcpu_fatal_exit( vt, e, frame );
    TRACE( "fault %s code %#x at %p (far %#llx)\n", vel1_fault_class_name( e->fclass ), (UINT)rec.ExceptionCode,
           rec.ExceptionAddress, (unsigned long long)e->far );
    if (rec.ExceptionCode == STATUS_ACCESS_VIOLATION && !virtual_handle_fault( &rec, (void *)frame->sp ))
    {
        if (prof_interval) vt->prof_charge = &prof_extra[VCPU_PROF_FAULT_HANDLED];
        vcpu_store_full( vt, frame );  /* guard page, write watch or stack growth handled: retry */
        return;
    }
    if (e->fclass == VEL1_FC_BRK && (e->esr & 0xffff) == 0xf003)
        vcpu_raise_exception_second_chance( frame, &rec );  /* __fastfail: no user handlers, as on the EL0 path */
    else
        vcpu_raise_exception( frame, &rec, pc_adjust );
    vcpu_store_full( vt, frame );
}

/* hv_vcpu_run returned HV_SUCCESS with HV_EXIT_REASON_UNKNOWN (no syndrome, no pc). Seen in the full Steam bottle
 * (2026-09-25): 1-8 per run, only while the UI was in use and with the host deep in swap, each killing a whole
 * renderer or the network service. No other exit reason is lost with it, so treat it like a kick exit: take the
 * registers, honour a kick it may have swallowed (the loop checks vel1_kick_take after any exit), write them back and
 * re-enter. A vCPU that keeps returning it is really stuck: that stays fatal. */
static BOOL vcpu_spurious_unknown( struct vcpu_thread *vt, const vel1_exit *e )
{
    static _Atomic uint64_t count;
    uint64_t n;

    if (e->hv_reason != HV_EXIT_REASON_UNKNOWN || e->hv_err || e->err) return FALSE;
    if (++vt->unknown_run > 64) return FALSE;
    vt->unknown_exits++;
    n = atomic_fetch_add_explicit( &count, 1, memory_order_relaxed ) + 1;
    if (n <= 32 || !(n & 0xff))
        fprintf( stderr, "wine: vCPU mode: HV_EXIT_REASON_UNKNOWN #%llu in pid %d, thread %04x (run of %u; exits %llu "
                 "kicks %llu faults %llu): re-entering\n", (unsigned long long)n, (int)getpid(),
                 (UINT)GetCurrentThreadId(), vt->unknown_run, (unsigned long long)vt->exits,
                 (unsigned long long)vt->kicks, (unsigned long long)vt->faults );
    return TRUE;
}

/***********************************************************************
 *           vcpu_loop
 *
 * Run the thread's guest code until NtCallbackReturn ends this level (nested callbacks); level 0 never returns.
 */
static void vcpu_loop( struct vcpu_thread *vt, struct vcpu_level *level )
{
    struct syscall_frame *frame;
    vel1_exit e;
    vel1_exit_kind kind;
    ULONG64 ret;
    int jmp;

    level->prev = vt->level;
    vt->level = level;

    if ((jmp = setjmp( level->resume )))
    {
        /* handle_syscall_fault: a host fault inside the syscall; it returns the exception code */
        ret = (ULONG)jmp;  /* zero-extended, as the EL0 path puts ExceptionCode in x0 */
        kind = level->kind;
        level->dispatching = FALSE;
        goto syscall_return;
    }

    for (;;)
    {
        kind = vcpu_run( vt, &e );
        frame = get_syscall_frame();
        if (kind == VEL1_EXIT_UNKNOWN && vcpu_spurious_unknown( vt, &e )) kind = VEL1_EXIT_KICK;
        else vt->unknown_run = 0;
        switch (kind)
        {
        case VEL1_EXIT_SYSCALL:
            vcpu_frame_from_syscall_exit( frame, &e );
            if (prof_interval)
            {
                vt->prof_charge = prof_sys_bucket( frame->syscall_id );
                if (!vt->wait_t0 && prof_sys_blocks( frame->syscall_id )) prof_wait_start( vt );
            }
            break;
        case VEL1_EXIT_UNIX_CALL:
            vcpu_frame_from_unix_call_exit( frame, &e );
            if (prof_interval)
            {
                vt->prof_charge = prof_unix_bucket( (const void *)e.regs.x[0], e.regs.x[1] );
                vt->prof_unix = TRUE;
            }
            break;
        case VEL1_EXIT_KICK:
        case VEL1_EXIT_FAULT_SYNC:
        case VEL1_EXIT_ILLEGAL:
        case VEL1_EXIT_TRAP:
        {
            vel1_regs regs;
            int err;

            vt->hv_depth++;
            err = vel1_regs_get( &vt->vcpu, &regs, VCPU_FULL_CORE_MASK, VEL1_R_ALL_SIMD );
            vt->hv_depth--;
            if (err) vcpu_fatal_exit( vt, &e, NULL );
            vcpu_frame_from_regs( frame, &regs );
            break;
        }
        default:
            vcpu_fatal_exit( vt, &e, NULL );
        }

        /* from here to the dispatch (or the register write-back after a fault or kick) this is signal-handler work:
         * run it with what the handlers block, as they would */
        vcpu_block_signals( NULL );
        atomic_store( &vt->in_syscall, 1 );
        atomic_signal_fence( memory_order_seq_cst );
        /* a KICK exit already consumed its kick; any exit may carry one left pending (D15) */
        if (vel1_kick_take( &vt->vcpu ) || kind == VEL1_EXIT_KICK)
        {
            vt->kicks++;
            if (!atomic_load( &vt->quit ))
                vcpu_suspend( frame, kind == VEL1_EXIT_SYSCALL || kind == VEL1_EXIT_UNIX_CALL );
        }
        if (atomic_load( &vt->quit )) abort_thread( 0 );

        switch (kind)
        {
        case VEL1_EXIT_SYSCALL:
            vt->syscalls++;
            level->kind = kind;
            vcpu_unblock_signals();  /* syscalls run with signals deliverable, as in the EL0 mode */
            level->dispatching = TRUE;
            ret = vcpu_dispatch_syscall( frame, &e );
            level->dispatching = FALSE;
            break;
        case VEL1_EXIT_UNIX_CALL:
            vt->unix_calls++;
            level->kind = kind;
            vcpu_unblock_signals();
            level->dispatching = TRUE;
            ret = ((const unixlib_entry_t *)e.regs.x[0])[e.regs.x[1]]( (void *)e.regs.x[2] );
            level->dispatching = FALSE;
            break;
        case VEL1_EXIT_KICK:
            vcpu_store_full( vt, frame );
            continue;
        default:
            vcpu_handle_fault( vt, frame, &e );
            continue;
        }

    syscall_return:
        if (level->done)
        {
            vt->level = level->prev;
            return;
        }
        vcpu_return( vt, level, kind, ret );
    }
}

/***********************************************************************
 *           vcpu_thread_start
 *
 * Replaces the jump to __wine_syscall_dispatcher_return at the end of signal_start_thread: the thread's user mode
 * runs in its own vCPU from here on.
 */
void DECLSPEC_NORETURN vcpu_thread_start( struct syscall_frame *frame )
{
    struct vcpu_thread *vt = calloc( 1, sizeof(*vt) );
    struct vcpu_level level;
    int ret;

    if (!vt) vcpu_fatal( "out of memory for thread %04x\n", (UINT)GetCurrentThreadId() );
    memset( &vt->cfg, 0, sizeof(vt->cfg) );
    vt->cfg.ttbr0 = gmm_ttbr0( gmm );
    vt->cfg.blob_va = vcpu_blob_va();
    vt->cfg.sp_el1 = frame->sp;
    vt->cfg.pc = frame->pc;
    vt->cfg.cpsr = frame->cpsr;
    vt->cfg.x0 = frame->x[0];
    vcpu_block_signals( NULL );  /* no SIGQUIT between the create and the publish; vcpu_store_full unblocks */
    /* counted before the slot wait: "threads" is every Windows thread that exists, queued ones included */
    {
        int live = atomic_fetch_add( &prof_threads_live, 1 ) + 1, peak = atomic_load( &prof_threads_peak );
        while (live > peak && !atomic_compare_exchange_weak( &prof_threads_peak, &peak, live )) ;
    }
    vt->unblock_fd = ntdll_get_thread_data()->wait_fd[1];
    if (vcpu_mn)
    {
        if ((ret = vel1_pool_member_init( &vcpu_pool, &vt->pool_member, 0 )))
            vcpu_fatal( "vel1_pool_member_init for thread %04x failed %d\n", (UINT)GetCurrentThreadId(), ret );
        vcpu_pool_acquire( vt );
    }
    if ((ret = vcpu_create( &vt->vcpu, &vt->cfg )))
    {
        char line[256] = "";
        if (vcpu_mn) vcpu_pool_line( line, sizeof(line) );
        vcpu_fatal( "vel1_vcpu_create for thread %04x failed %d (hv %#x; at most %u vCPUs per process, %d live) %s\n",
                    (UINT)GetCurrentThreadId(), ret, vt->vcpu.last_hv_err, VEL1_MAX_VCPUS - 1,
                    atomic_load( &prof_vcpus_live ), line );
    }
    vt->has_vcpu = TRUE;
    vcpu_note_vcpu_up();
    pthread_setspecific( vcpu_key, vt );
    atomic_store( &vt->in_syscall, 1 );
    vcpu_store_full( vt, frame );
    vcpu_note_entered();  /* before the first vel1_run: from now on gmm's TLBIs are real */
    TRACE( "thread %04x: vCPU up, pc %#llx sp %#llx\n", (UINT)GetCurrentThreadId(), (unsigned long long)frame->pc,
           (unsigned long long)frame->sp );
    memset( &level, 0, sizeof(level) );
    vcpu_loop( vt, &level );
    vcpu_fatal( "level 0 of thread %04x returned\n", (UINT)GetCurrentThreadId() );
}

/***********************************************************************
 *           vcpu_user_mode_callback
 *
 * KeUserModeCallback: run KiUserCallbackDispatcher on this thread's vCPU in a nested frame and loop until its
 * NtCallbackReturn. The outer syscall's registers come back from the outer frame when it returns.
 */
NTSTATUS vcpu_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len )
{
    struct vcpu_thread *vt = vcpu_current();
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    struct syscall_frame *outer = thread_data->syscall_frame, inner;
    struct vcpu_level level, *outer_level = vt->level;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)user_sp;
    void *exception_list = NtCurrentTeb()->Tib.ExceptionList;  /* call_user_mode_callback saves and restores it */
    vel1_regs regs;
    int err;

    if (thread_data->syscall_trace) trace_usercall( stack->id, (ULONG_PTR *)stack->args, stack->len );
    if (vcpu_mn) vcpu_ensure( vt );  /* the syscall that dispatches this callback may have blocked and released */

    /* a unix-call exit saved only q8-q15 and no FPCR/FPSR, and the outer return rewrites all of them after a
     * callback: take the exact FP state from the vCPU, once per exit (before the first callback runs other guest
     * code on it), unless a context change already set it. A syscall exit saved all of it. */
    if (outer_level->kind == VEL1_EXIT_UNIX_CALL && !outer_level->callback_ran)
    {
        sigset_t old;

        vcpu_block_signals( &old );
        if (!(outer->restore_flags & (CONTEXT_FLOATING_POINT & ~CONTEXT_ARM64)))
        {
            vt->hv_depth++;
            err = vel1_regs_get( &vt->vcpu, &regs, VEL1_R_FPCR | VEL1_R_FPSR, VEL1_R_ALL_SIMD );
            vt->hv_depth--;
            if (err) vcpu_fatal( "vel1_regs_get(fp) failed %d\n", err );
            outer->fpcr = regs.fpcr;
            outer->fpsr = regs.fpsr;
            memcpy( outer->v, regs.v, sizeof(outer->v) );
        }
        pthread_sigmask( SIG_SETMASK, &old, NULL );
    }

    TRACE( "user callback: user_sp %#llx, from a %s exit\n", (unsigned long long)user_sp,
           outer_level->kind == VEL1_EXIT_UNIX_CALL ? "unix-call" : "syscall" );
    memset( &inner, 0, sizeof(inner) );
    inner.prev_frame = outer;
    inner.sp = user_sp;
    inner.pc = (ULONG64)pKiUserCallbackDispatcher;
    inner.x[0] = user_sp;
    inner.x[18] = (ULONG64)NtCurrentTeb();
    inner.cpsr = outer->cpsr;
    thread_data->syscall_frame = &inner;

    memset( &regs, 0, sizeof(regs) );
    regs.x[0] = inner.x[0];
    regs.x[18] = inner.x[18];
    regs.sp_el1 = inner.sp;
    regs.pc = inner.pc;
    atomic_store( &vt->in_syscall, 0 );
    vt->hv_depth++;
    err = vel1_regs_set( &vt->vcpu, &regs, VEL1_R_X(0) | VEL1_R_X(18) | VEL1_R_SP_EL1 | VEL1_R_PC, 0 );
    vt->hv_depth--;
    if (err) vcpu_fatal( "vel1_regs_set(callback) failed %d\n", err );

    if (prof_interval && vt->wait_t0) vt->wait_cbs++;
    memset( &level, 0, sizeof(level) );
    vcpu_loop( vt, &level );

    thread_data->syscall_frame = outer;
    vt->level = outer_level;
    outer_level->callback_ran = TRUE;
    atomic_store( &vt->in_syscall, 1 );
    *ret_ptr = level.cb_ret_ptr;
    *ret_len = level.cb_ret_len;
    NtCurrentTeb()->Tib.ExceptionList = exception_list;
    if (thread_data->syscall_trace) trace_userret( level.cb_ret_ptr, level.cb_ret_len, level.cb_status, stack->id );
    TRACE( "user callback done: status %#x, %u bytes\n", (unsigned int)level.cb_status, (unsigned int)level.cb_ret_len );
    return level.cb_status;
}

/***********************************************************************
 *           vcpu_callback_return
 *
 * NtCallbackReturn: end the innermost vcpu_loop level; its caller (vcpu_user_mode_callback) returns the result.
 */
NTSTATUS vcpu_callback_return( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    struct vcpu_thread *vt = vcpu_current();
    struct vcpu_level *level = vt->level;

    if (!get_syscall_frame()->prev_frame || !level->prev) return STATUS_NO_CALLBACK_ACTIVE;
    level->cb_ret_ptr = ret_ptr;
    level->cb_ret_len = ret_len;
    level->cb_status = status;
    level->done = TRUE;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           vcpu_signal_kick
 *
 * From usr1_handler / quit_handler, on the thread itself. If the thread is in (or about to enter) the guest, kick
 * the vCPU and return TRUE: the loop handles the request from the full guest state. Otherwise return FALSE and the
 * handler takes the existing in-syscall path against the frame. No hv_* call (vcpu_el1.h D8).
 */
BOOL vcpu_signal_kick( BOOL quit )
{
    struct vcpu_thread *vt = vcpu_current();

    if (!vt) return FALSE;
    if (quit) atomic_store( &vt->quit, 1 );
    if (atomic_load( &vt->in_syscall )) return FALSE;
    if (vel1_kick_self( &vt->vcpu ) == VEL1_KICK_SIGNAL_FAILED)
    {
        /* the kick stays pending in vel1 (D8); the loop will see it at its next entry. In a signal handler: no ERR */
        static const char msg[] = "wine: vCPU mode: kick signal failed (kicker semaphore)\n";
        write( 2, msg, sizeof(msg) - 1 );
        vt->kick_failures++;
    }
    return TRUE;
}

/***********************************************************************
 *           vcpu_syscall_fault_resume
 *
 * handle_syscall_fault: where a host fault inside a syscall returns to, or NULL (the fault is not inside a
 * syscall dispatched by the loop: a host bug).
 */
void *vcpu_syscall_fault_resume(void)
{
    struct vcpu_thread *vt = vcpu_current();

    if (!vt || !vt->level || !vt->level->dispatching || !atomic_load( &vt->in_syscall ) || vt->hv_depth)
        return NULL;
    return vt->level->resume;
}

/***********************************************************************
 *           vcpu_thread_exit
 *
 * On the exiting thread, before pthread_exit: give the vCPU back (vcpu_el1.h D16).
 */
void vcpu_thread_exit(void)
{
    struct vcpu_thread *vt;
    int ret;

    if (!vcpu_mode || !(vt = vcpu_current())) return;
    if (vt->hv_depth || vel1_in_guest( &vt->vcpu ))
    {
        ERR( "thread %04x exits inside a vel1 call: its vCPU slot leaks\n", (UINT)GetCurrentThreadId() );
        return;
    }
    {
        sigset_t all;  /* the thread is exiting: nothing may interrupt the destroy (vel1 locks, HVF) */
        sigfillset( &all );
        pthread_sigmask( SIG_BLOCK, &all, NULL );
    }
    pthread_setspecific( vcpu_key, NULL );
    atomic_fetch_sub( &prof_threads_live, 1 );
    if (vt->wait_t0) atomic_fetch_sub( &prof_parked, 1 );  /* ended inside a wait (NtTerminateThread) */
    if (vt->has_vcpu)
    {
        if ((ret = vel1_vcpu_destroy( &vt->vcpu )))
        {
            ERR( "vel1_vcpu_destroy failed %d: the slot stays taken (D16)\n", ret );
            return;  /* stranded: vt stays allocated, the monitor may still walk its member */
        }
        atomic_fetch_sub( &prof_vcpus_live, 1 );
        if (vcpu_mn) vel1_pool_release( &vcpu_pool, &vt->pool_member );
    }
    if (vcpu_mn && (ret = vel1_pool_member_fini( &vcpu_pool, &vt->pool_member )))
    {
        ERR( "vel1_pool_member_fini failed %d\n", ret );
        return;
    }
    free( vt );
}

/***********************************************************************
 *           vcpu_init_process
 *
 * Called first thing in virtual_init, before any view exists. No-op unless PMW_VCPU is set.
 */
void vcpu_init_process(void)
{
    static const gmm_backend_t backend = { .s2_map = s2_map, .s2_unmap = s2_unmap, .tlbi_sync = tlbi_sync };
    const char *env = getenv( "PMW_VCPU" );
    gmm_config_t cfg;
    vel1_vm_info info;
    pthread_t thread;
    sigset_t old;
    void *pool;
    uint64_t start = mach_absolute_time();
    int ret;

    memset( &info, 0, sizeof(info) );
    if (!env || !*env || !strcmp( env, "0" )) return;
    vcpu_mode = strcmp( env, "selftest" ) ? 1 : 2;
    if (pthread_key_create( &vcpu_key, NULL )) vcpu_fatal( "pthread_key_create failed\n" );

    block_all_signals( &old );  /* the kicker thread inherits this */
    ret = vel1_vm_create( vel1_hv_live_ops(), VCPU_IPA_BITS, &info );
    pthread_sigmask( SIG_SETMASK, &old, NULL );
    if (ret) vcpu_fatal( "vel1_vm_create(%u-bit IPA): %d (hv %#x, max %u)\n", VCPU_IPA_BITS, ret, info.hv_err,
                         info.max_ipa_bits );

    pool = gmm_alloc_backing( VCPU_PT_POOL_SIZE );
    if (!pool) vcpu_fatal( "page-table pool allocation failed\n" );
    /* a fork() child sharing the page tables would leave the vCPUs walking copies gmm no longer writes */
    if (minherit( pool, VCPU_PT_POOL_SIZE, VM_INHERIT_NONE )) vcpu_fatal( "page-table pool minherit failed\n" );
    memset( &cfg, 0, sizeof(cfg) );
    cfg.alias_base = VCPU_ALIAS_BASE;
    cfg.ipa_lo = VCPU_DATA_IPA_LO;
    cfg.ipa_hi = VCPU_DATA_IPA_HI;
    cfg.pt_pool_ipa = VCPU_PT_POOL_IPA;
    cfg.pt_pool_host = pool;
    cfg.pt_pool_sz = VCPU_PT_POOL_SIZE;
    cfg.t0sz = 16;
    /* gmm's load cost (docs/macos/relay-to-openrosetta-gmm-cost-2026-09-24.md, answered in openrosetta
     * docs/relays/fex-side-reply-tso-gmm-qpc-2026-09-24.md): Slay the Spire 2's ~240 us per stage-1 sync was
     * GMM_CFG_PARANOID (a region query per chunk before every stage-2 map and unmap) plus one stage-2 map, and so one
     * backing guard query, per 16K chunk. gmm alone, 128 chunks: 208-284 -> 14 us a commit, 134-187 -> 15 us a
     * decommit with both changed. PARANOID is a debugging cross-check of the ordering rule and stays available
     * (PMW_VCPU_PARANOID=1); the backing guard before every stage-2 map is not affected by it.
     * Multi-chunk runs revoke with GMM_CFG_S2_REMAP: a revoke inside a run unmaps the whole run and re-maps its
     * survivors, so no chunk is ever left stage-2 mapped behind a revoke ("retained", the split policy's answer to a
     * refused sub-range unmap), and virtual.c may change the host mapping as soon as the revoke returns.
     * PMW_VCPU_S2_RUN=<chunks> sets the run cap (1 = the old per-chunk mapping). */
    {
        BOOL paranoid = (env = getenv( "PMW_VCPU_PARANOID" )) && !strcmp( env, "1" );
        long run = (env = getenv( "PMW_VCPU_S2_RUN" )) ? strtol( env, NULL, 10 ) : 128;

        cfg.flags = paranoid ? GMM_CFG_PARANOID : 0;
        cfg.s2_run_chunks = run > 1 ? (run > 4096 ? 4096 : (unsigned)run) : 1;
        if (cfg.s2_run_chunks > 1) cfg.flags |= GMM_CFG_S2_REMAP;
        if ((ret = gmm_init( &gmm, &cfg, &backend ))) vcpu_fatal( "gmm_init: %d\n", ret );
        /* with S2_REMAP nothing is retained, so virtual.c's stage-2 assertion is a paranoid check like gmm's */
        vcpu_check_s2 = paranoid;
        TRACE( "gmm: s2_run_chunks %u, flags %#x\n", cfg.s2_run_chunks, cfg.flags );
    }
    vcpu_sect_alias = VCPU_GMM_SECT && !((env = getenv( "PMW_VCPU_SECT_ALIAS" )) && !strcmp( env, "0" ));
    /* wineserver backs anonymous sections with POSIX shm under the same variable (server/mapping.c). Default on since
     * 2026-09-25 (G14 live PASS on the FEX side, shmtest, STS2 on screen); PMW_VCPU_SHARED_SECTIONS=0 turns it off */
    vcpu_shared_sections = vcpu_sect_alias && !((env = getenv( "PMW_VCPU_SHARED_SECTIONS" )) && atoi( env ) <= 0);

    init_sys_page();
    init_kuser();
    prof_start();

    block_all_signals( &old );
    ret = pthread_create( &thread, NULL, tlbi_thread, NULL );
    pthread_sigmask( SIG_SETMASK, &old, NULL );
    if (ret) vcpu_fatal( "TLBI executor thread: %d\n", ret );
    pthread_detach( thread );
    pthread_mutex_lock( &tlbi_mutex );
    while (!tlbi_ready) pthread_cond_wait( &tlbi_cond, &tlbi_mutex );
    ret = tlbi_status;
    pthread_mutex_unlock( &tlbi_mutex );
    if (ret) vcpu_fatal( "TLBI executor vCPU failed\n" );

    vcpu_mn = vcpu_mode == 1 && !((env = getenv( "PMW_VCPU_MN" )) && atoi( env ) <= 0);
    if (vcpu_mn)
    {
        vel1_pool_cfg pc = VEL1_POOL_CFG_DEFAULT;

        if ((ret = vel1_pool_init( &vcpu_pool, &pc ))) vcpu_fatal( "vel1_pool_init: %d\n", ret );
        block_all_signals( &old );  /* the monitor thread inherits this (R10) */
        ret = vel1_pool_monitor_start2( &vcpu_pool, vcpu_pool_kick, vcpu_pool_unblock, NULL );
        pthread_sigmask( SIG_SETMASK, &old, NULL );
        if (ret) vcpu_fatal( "vel1_pool_monitor_start2: %d\n", ret );
        TRACE( "M:N on: %u slots, low_water %u, sleepy %llu ms, quantum %llu ms\n", pc.slots, pc.low_water,
               (unsigned long long)pc.sleepy_ns / 1000000, (unsigned long long)pc.quantum_ns / 1000000 );
    }
    else TRACE( "M:N off (PMW_VCPU_MN=0)\n" );

    TRACE( "VM up in %.1f us: IPA %u bits (max %u), hardware TSO %s, sys page %p, KUSER host %p\n",
           ticks_to_us( mach_absolute_time() - start ), info.ipa_bits, info.max_ipa_bits,
           atomic_load( &tso_state ) > 0 ? "yes" : "NO", sys_page, kuser_host );
    if (vcpu_mode == 2) vcpu_selftest();
}

/***********************************************************************
 * KUSER_SHARED_DATA publisher
 *
 * The server rewrites the time fields of its shared page every 16 ms; the guest reads 0x7ffe0000, a gmm page. Copy
 * the page over every 8 ms: the KSYSTEM_TIME fields with the reader protocol on the source side and the server's
 * store order (High2Time, LowPart, High1Time) on ours, everything else as plain bytes.
 */
static const unsigned int kuser_time_offsets[] =
{
    FIELD_OFFSET( KUSER_SHARED_DATA, InterruptTime ),
    FIELD_OFFSET( KUSER_SHARED_DATA, SystemTime ),
    FIELD_OFFSET( KUSER_SHARED_DATA, TimeZoneBias ),
    FIELD_OFFSET( KUSER_SHARED_DATA, TickCount ),
};

static void publish_ksystem_time( volatile KSYSTEM_TIME *dst, const volatile KSYSTEM_TIME *src )
{
    LONG high1, high2;
    ULONG low;

    do
    {
        high1 = src->High1Time;
        __atomic_thread_fence( __ATOMIC_ACQUIRE );
        low = src->LowPart;
        __atomic_thread_fence( __ATOMIC_ACQUIRE );
        high2 = src->High2Time;
    } while (high1 != high2);
    dst->High2Time = high1;
    __atomic_thread_fence( __ATOMIC_RELEASE );
    dst->LowPart = low;
    __atomic_thread_fence( __ATOMIC_RELEASE );
    dst->High1Time = high1;
}

/* PMW_VCPU_FAST_QPC=1: the guest's RtlQueryPerformanceCounter reads CNTVCT_EL0 (== mach_absolute_time() on every
 * vCPU, vcpu_el1 [D19]) plus QpcBias instead of making a syscall, while QpcFrequency is TICKSPERSEC. The bias is
 * mach_continuous_time() - mach_absolute_time(): the time the Mac slept since boot. It is only moved forward, and
 * only by more than 0.5 ms (so the reader's clock stays monotonic); after a wake the guest runs behind the host by
 * the sleep for at most one republish (8 ms). Both fields are written only here, never copied from the server's
 * page (copy_kuser_range skips them), so a reader never pairs the enabled frequency with a zero bias. */
static BOOL fast_qpc;
static ULONGLONG qpc_bias;

static void publish_qpc_bias( char *dst )
{
    ULONGLONG bias = mach_continuous_time() - mach_absolute_time();

    if (bias > qpc_bias + 12000) qpc_bias = bias;  /* 0.5 ms at 24 MHz */
    __atomic_store_n( (volatile ULONGLONG *)(dst + FIELD_OFFSET( KUSER_SHARED_DATA, QpcBias )), qpc_bias,
                      __ATOMIC_RELEASE );
}

/* plain bytes of [from, to), leaving the QPC fields alone while fast QPC owns them */
static void copy_kuser_range( char *dst, const char *src, unsigned int from, unsigned int to )
{
    const unsigned int holes[2] = { FIELD_OFFSET( KUSER_SHARED_DATA, QpcFrequency ),
                                    FIELD_OFFSET( KUSER_SHARED_DATA, QpcBias ) };
    unsigned int i;

    for (i = 0; fast_qpc && i < ARRAY_SIZE(holes); i++)
    {
        if (holes[i] < from || holes[i] >= to) continue;
        memcpy( dst + from, src + from, holes[i] - from );
        from = holes[i] + sizeof(ULONGLONG);
    }
    memcpy( dst + from, src + from, to - from );
}

static void publish_kuser( char *dst, const char *src )
{
    unsigned int i, pos = 0;

    for (i = 0; i < ARRAY_SIZE(kuser_time_offsets); i++)
    {
        unsigned int off = kuser_time_offsets[i];
        copy_kuser_range( dst, src, pos, off );
        publish_ksystem_time( (volatile KSYSTEM_TIME *)(dst + off), (const volatile KSYSTEM_TIME *)(src + off) );
        pos = off + sizeof(KSYSTEM_TIME);
    }
    copy_kuser_range( dst, src, pos, 0x1000 );
    if (!fast_qpc) return;
    /* the bias before the frequency that enables it (the first publish), and never a transient zero */
    publish_qpc_bias( dst );
    __atomic_store_n( (volatile LONGLONG *)(dst + FIELD_OFFSET( KUSER_SHARED_DATA, QpcFrequency )),
                      (LONGLONG)10000000, __ATOMIC_RELEASE );
}

static void *kuser_thread( void *arg )
{
    for (;;)
    {
        publish_kuser( kuser_host, arg );
        usleep( 8000 );
    }
    return NULL;
}

void vcpu_start_kuser_publisher( const void *src )
{
    const char *env = getenv( "PMW_VCPU_FAST_QPC" );
    pthread_t thread;
    sigset_t old;
    int ret;

    fast_qpc = env && !strcmp( env, "1" );
    TRACE( "fast QPC %s\n", fast_qpc ? "on" : "off" );

    publish_kuser( kuser_host, src );
    block_all_signals( &old );
    ret = pthread_create( &thread, NULL, kuser_thread, (void *)src );
    pthread_sigmask( SIG_SETMASK, &old, NULL );
    if (ret) vcpu_fatal( "KUSER publisher thread: %d\n", ret );
    pthread_detach( thread );
}

gmm_t *vcpu_gmm(void)
{
    return gmm;
}

uint64_t vcpu_blob_va(void)
{
    return (uint64_t)sys_page + SYS_BLOB_OFF;
}

void *vcpu_kuser_host(void)
{
    return kuser_host;
}

void vcpu_note_entered(void)
{
    atomic_store( &any_entered, 1 );
}

#endif /* __APPLE__ && __aarch64__ */
