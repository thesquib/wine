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

/* pure translation helpers (vcpu_pure_arm64.c) */
extern unsigned char vcpu_vprot_to_s1( unsigned char vprot );
extern BOOL vcpu_exit_to_exception( const vel1_exit *e, const struct syscall_frame *frame, EXCEPTION_RECORD *rec,
                                    ULONG64 *pc_adjust );
extern void vcpu_frame_from_syscall_exit( struct syscall_frame *frame, const vel1_exit *e );
extern void vcpu_frame_from_unix_call_exit( struct syscall_frame *frame, const vel1_exit *e );
extern void vcpu_frame_from_regs( struct syscall_frame *frame, const vel1_regs *r );
extern void vcpu_regs_from_frame( vel1_regs *r, const struct syscall_frame *frame );
extern void vcpu_return_plan( const struct syscall_frame *frame, ULONG64 retval, BOOL callback_ran, vel1_regs *r,
                              uint64_t *core_mask, uint32_t *simd_mask );

#endif /* __APPLE__ */
#endif /* __aarch64__ */
#endif /* __WINE_NTDLL_UNIX_VCPU_ARM64_H */
