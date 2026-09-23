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
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(vcpu);

/* the +syscall relay tracing of user callbacks (loader.c; the EL0 path calls them from asm) */
extern void trace_usercall( UINT id, ULONG_PTR *args, ULONG len );
extern void trace_userret( void *ret_ptr, ULONG len, NTSTATUS status, UINT id );

int vcpu_mode;
int vcpu_check_s2;

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
    return hv_vm_map( host, ipa, size, flags );
}

static uint32_t s2_unmap( uint64_t ipa, size_t size )
{
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

static int tlbi_sync( void *ctx, const uint64_t *va, size_t count, int all )
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

struct vcpu_thread
{
    vel1_vcpu           vcpu;          /* host-only memory (D12); the thread finds it through vcpu_key */
    atomic_int          in_syscall;
    atomic_int          quit;
    volatile sig_atomic_t hv_depth;    /* inside a vel1 call: never destroy the vCPU from a handler then */
    struct vcpu_level  *level;
    uint64_t            exits, syscalls, unix_calls, faults, kicks, kick_failures;
};

static pthread_key_t vcpu_key;

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

    if (!vt || vt->hv_depth || !(all || (count && count <= VEL1_TLBI_MAX_VA))) return 1;
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

static vel1_exit_kind vcpu_run( struct vcpu_thread *vt, vel1_exit *e )
{
    vel1_exit_kind kind;

    for (;;)
    {
        vt->hv_depth++;
        kind = vel1_run( &vt->vcpu, e );
        vt->hv_depth--;
        vt->exits++;
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

/* write the whole frame into the vCPU and leave the syscall state (fault, kick, thread start) */
static void vcpu_store_full( struct vcpu_thread *vt, const struct syscall_frame *frame )
{
    struct syscall_frame entry;
    vel1_regs regs;
    int ret;

    /* signals held back during the fault / kick handling arrive now, with the mark set: they take the host path
     * and edit the frame, which is read below */
    vcpu_unblock_signals();
    atomic_store( &vt->in_syscall, 0 );
    atomic_signal_fence( memory_order_seq_cst );
    if (frame->restore_flags & RESTORE_FLAGS_EMULATION)
    {
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

    atomic_store( &vt->in_syscall, 0 );
    atomic_signal_fence( memory_order_seq_cst );
    if (frame->restore_flags & RESTORE_FLAGS_EMULATION)
    {
        /* into x86 code: the emulator takes over with the frame as a CONTEXT, everything stored */
        struct syscall_frame entry;

        vcpu_emulation_entry( frame, &entry );
        vcpu_regs_from_frame( &regs, &entry );
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
    if (e->kind == VEL1_EXIT_FAULT_SYNC && (e->fclass == VEL1_FC_DATA_ABORT || e->fclass == VEL1_FC_INSN_ABORT))
    {
        switch (gmm_vm_fault( gmm, e->far, e->esr ))
        {
        case GMM_VF_RETRY:  /* a concurrent protection change already allows it */
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
        vcpu_store_full( vt, frame );  /* guard page, write watch or stack growth handled: retry */
        return;
    }
    if (e->fclass == VEL1_FC_BRK && (e->esr & 0xffff) == 0xf003)
        vcpu_raise_exception_second_chance( frame, &rec );  /* __fastfail: no user handlers, as on the EL0 path */
    else
        vcpu_raise_exception( frame, &rec, pc_adjust );
    vcpu_store_full( vt, frame );
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
        switch (kind)
        {
        case VEL1_EXIT_SYSCALL:
            vcpu_frame_from_syscall_exit( frame, &e );
            break;
        case VEL1_EXIT_UNIX_CALL:
            vcpu_frame_from_unix_call_exit( frame, &e );
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
    vel1_vcpu_cfg cfg;
    int ret;

    if (!vt) vcpu_fatal( "out of memory for thread %04x\n", (UINT)GetCurrentThreadId() );
    memset( &cfg, 0, sizeof(cfg) );
    cfg.ttbr0 = gmm_ttbr0( gmm );
    cfg.blob_va = vcpu_blob_va();
    cfg.sp_el1 = frame->sp;
    cfg.pc = frame->pc;
    cfg.cpsr = frame->cpsr;
    cfg.x0 = frame->x[0];
    vcpu_block_signals( NULL );  /* no SIGQUIT between the create and the publish; vcpu_store_full unblocks */
    if ((ret = vcpu_create( &vt->vcpu, &cfg )))
        vcpu_fatal( "vel1_vcpu_create for thread %04x failed %d (hv %#x; at most %u vCPUs per process)\n",
                    (UINT)GetCurrentThreadId(), ret, vt->vcpu.last_hv_err, VEL1_MAX_VCPUS - 1 );
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
    if ((ret = vel1_vcpu_destroy( &vt->vcpu ))) ERR( "vel1_vcpu_destroy failed %d\n", ret );
    else free( vt );
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
    memset( &cfg, 0, sizeof(cfg) );
    cfg.alias_base = VCPU_ALIAS_BASE;
    cfg.ipa_lo = VCPU_DATA_IPA_LO;
    cfg.ipa_hi = VCPU_DATA_IPA_HI;
    cfg.pt_pool_ipa = VCPU_PT_POOL_IPA;
    cfg.pt_pool_host = pool;
    cfg.pt_pool_sz = VCPU_PT_POOL_SIZE;
    cfg.t0sz = 16;
    cfg.flags = GMM_CFG_PARANOID;
    /* multi-chunk runs (> 1) also need GMM_CFG_S2_REMAP, or virtual.c skipping the host change of a retained chunk:
     * without them a refused sub-range unmap retains chunks, and vcpu_assert_s2_unmapped aborts on the next
     * ordinary decommit or free there */
    cfg.s2_run_chunks = 1;
    if ((ret = gmm_init( &gmm, &cfg, &backend ))) vcpu_fatal( "gmm_init: %d\n", ret );
    vcpu_check_s2 = cfg.s2_run_chunks > 1 || ((env = getenv( "PMW_VCPU_PARANOID" )) && !strcmp( env, "1" ));

    init_sys_page();
    init_kuser();

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

static void publish_kuser( char *dst, const char *src )
{
    unsigned int i, pos = 0;

    for (i = 0; i < ARRAY_SIZE(kuser_time_offsets); i++)
    {
        unsigned int off = kuser_time_offsets[i];
        memcpy( dst + pos, src + pos, off - pos );
        publish_ksystem_time( (volatile KSYSTEM_TIME *)(dst + off), (const volatile KSYSTEM_TIME *)(src + off) );
        pos = off + sizeof(KSYSTEM_TIME);
    }
    memcpy( dst + pos, src + pos, 0x1000 - pos );
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
    pthread_t thread;
    sigset_t old;
    int ret;

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
