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
#include "unix_private.h"
#include "vcpu_arm64.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(vcpu);

int vcpu_mode;

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
    ret = vel1_vcpu_create( &tlbi_vcpu, &cfg );

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
    if ((ret = vel1_vcpu_create( v, &cfg )))
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
    fprintf( stderr, "vcpu selftest: hardware PASS (VM %d-bit IPA, sys page %p, KUSER host %p, ttbr0 %#llx)\n",
             VCPU_IPA_BITS, sys_page, kuser_host, (unsigned long long)gmm_ttbr0( gmm ));
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

    memset( &regs, 0, sizeof(regs) );
    regs.x[0] = va;
    regs.x[1] = value;
    regs.x[3] = 0xdeadbeefdeadbeefull;
    if (vel1_resume_at( v, (uint64_t)sys_page + SYS_PROBE_OFF, 0 ) ||
        vel1_regs_set( v, &regs, VEL1_R_X(0) | VEL1_R_X(1) | VEL1_R_X(3), 0 )) return VEL1_EXIT_ERROR;
    kind = vel1_run( v, e );
    if (kind == VEL1_EXIT_HOSTCALL && e->hvc_imm != VCPU_HVC_PROBE_DONE) return VEL1_EXIT_UNKNOWN;
    if (kind == VEL1_EXIT_HOSTCALL && old)
    {
        if (vel1_regs_get( v, &regs, VEL1_R_X(3), 0 )) return VEL1_EXIT_ERROR;
        *old = regs.x[3];
    }
    return kind;
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
    cfg.s2_run_chunks = 1;
    if ((ret = gmm_init( &gmm, &cfg, &backend ))) vcpu_fatal( "gmm_init: %d\n", ret );

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

    TRACE( "VM up in %.1f us: IPA %u bits (max %u), sys page %p, KUSER host %p\n",
           ticks_to_us( mach_absolute_time() - start ), info.ipa_bits, info.max_ipa_bits, sys_page, kuser_host );
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
