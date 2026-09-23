/*
 * arm64 vCPU mode: run every Windows thread's user-mode code at EL1 in a Hypervisor.framework vCPU
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

#ifndef __WINE_NTDLL_UNIX_VCPU_ARM64_H
#define __WINE_NTDLL_UNIX_VCPU_ARM64_H

/* PMW_VCPU: 0 off (the EL0 path, unchanged), 1 on, 2 selftest. A constant 0 everywhere but arm64 macOS, so every
 * "if (vcpu_mode)" branch compiles away there. */
#if defined(__APPLE__) && defined(__aarch64__)
extern int vcpu_mode;
extern void vcpu_init_process(void);
extern void vcpu_start_kuser_publisher( const void *src );
extern void vcpu_thread_exit(void);
#else
#define vcpu_mode 0
static inline void vcpu_init_process(void) {}
static inline void vcpu_start_kuser_publisher( const void *src ) {}
static inline void vcpu_thread_exit(void) {}
#endif

#ifdef __aarch64__

/* The per-thread user-mode register frame, at the top of the kernel stack. In the vCPU mode it stays the single
 * source of truth for the thread's user-mode state: the loop fills it from vCPU exits and writes it back. */
struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 align;          /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );

#define RESTORE_FLAGS_EMULATION  0x00010000

#if defined(__APPLE__)

#include "vcpu/vcpu_el1.h"
#include "vcpu/gmm.h"

/* virtual.c's page protection bits (VPROT_*), which are private to it; virtual.c checks they match */
#define VCPU_VPROT_READ       0x01
#define VCPU_VPROT_WRITE      0x02
#define VCPU_VPROT_EXEC       0x04
#define VCPU_VPROT_WRITECOPY  0x08
#define VCPU_VPROT_GUARD      0x10
#define VCPU_VPROT_COMMITTED  0x20
#define VCPU_VPROT_WRITEWATCH 0x40

/* everything but SP_EL0 and the TPIDRs: what a fault or kick exit loads and stores */
#define VCPU_FULL_CORE_MASK (VEL1_R_GPRS | VEL1_R_PC | VEL1_R_CPSR | VEL1_R_SP_EL1 | VEL1_R_FPCR | VEL1_R_FPSR)

/* process state (vcpu_arm64.c) */
extern gmm_t *vcpu_gmm(void);
extern uint64_t vcpu_blob_va(void);
extern void *vcpu_kuser_host(void);
extern void vcpu_note_entered(void);
extern vel1_exit_kind vcpu_selftest_probe( uint64_t va, uint64_t value, uint64_t *old, vel1_exit *e );

/* the thread loop (vcpu_arm64.c) */
extern void DECLSPEC_NORETURN vcpu_thread_start( struct syscall_frame *frame );
extern NTSTATUS vcpu_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len );
extern NTSTATUS vcpu_callback_return( void *ret_ptr, ULONG ret_len, NTSTATUS status );
extern BOOL vcpu_signal_kick( BOOL quit );
extern void *vcpu_syscall_fault_resume(void);

/* the kernel-stack layout KeUserModeCallback hands to KiUserCallbackDispatcher (signal_arm64.c builds it) */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

/* exception delivery and suspend against the frame (signal_arm64.c) */
extern void vcpu_raise_exception( struct syscall_frame *frame, EXCEPTION_RECORD *rec, ULONG64 pc_adjust );
extern void vcpu_raise_exception_second_chance( struct syscall_frame *frame, EXCEPTION_RECORD *rec );
extern void vcpu_suspend( struct syscall_frame *frame, BOOL in_syscall );

/* Apple-ABI shims for syscalls whose parameters Windows code passes differently (vcpu_shims_arm64.c, generated) */
struct vcpu_syscall_shim { const void *func, *shim; };
extern const struct vcpu_syscall_shim vcpu_syscall_shims[];
extern const unsigned int vcpu_syscall_shim_count;

/* pure translation helpers (vcpu_pure_arm64.c) */
extern unsigned char vcpu_vprot_to_s1( unsigned char vprot );
extern BOOL vcpu_exit_to_exception( const vel1_exit *e, const struct syscall_frame *frame, EXCEPTION_RECORD *rec,
                                    ULONG64 *pc_adjust );
extern void vcpu_frame_from_syscall_exit( struct syscall_frame *frame, const vel1_exit *e );
extern void vcpu_frame_from_unix_call_exit( struct syscall_frame *frame, const vel1_exit *e );
extern void vcpu_frame_from_regs( struct syscall_frame *frame, const vel1_regs *r );
extern void vcpu_regs_from_frame( vel1_regs *r, const struct syscall_frame *frame );
extern ULONG64 vcpu_call_syscall( void *func, const ULONG64 *regs, const ULONG64 *stack_args, ULONG64 stack_bytes );
extern void vcpu_return_plan( const struct syscall_frame *frame, ULONG64 retval, BOOL callback_ran, vel1_regs *r,
                              uint64_t *core_mask, uint32_t *simd_mask );

#endif /* __APPLE__ */
#endif /* __aarch64__ */
#endif /* __WINE_NTDLL_UNIX_VCPU_ARM64_H */
