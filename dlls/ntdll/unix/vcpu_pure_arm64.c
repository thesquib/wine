/*
 * arm64 vCPU mode: pure translation between vCPU exits, vCPU registers, the syscall frame and Windows exceptions
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

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)

#include "config.h"

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "vcpu_arm64.h"

/* CONTEXT_* bits as the asm dispatcher return tests them in restore_flags (without CONTEXT_ARM64) */
#define RF_INTEGER        (CONTEXT_INTEGER & ~CONTEXT_ARM64)
#define RF_FLOATING_POINT (CONTEXT_FLOATING_POINT & ~CONTEXT_ARM64)

/***********************************************************************
 *           vcpu_vprot_to_s1
 *
 * Page protection byte -> gmm's per-4K stage-1 target (the mapping gmm.h documents for Wine).
 */
unsigned char vcpu_vprot_to_s1( unsigned char vprot )
{
    unsigned char s1;

    if (!(vprot & VCPU_VPROT_COMMITTED)) return GMM_S1_NONE;
    s1 = GMM_S1_COMMIT;
    if (vprot & VCPU_VPROT_GUARD) return s1;
    if (vprot & VCPU_VPROT_READ) s1 |= GMM_S1_R;
    if (vprot & (VCPU_VPROT_WRITE | VCPU_VPROT_WRITECOPY)) s1 |= GMM_S1_R | GMM_S1_W;
    if (vprot & VCPU_VPROT_EXEC) s1 |= GMM_S1_R | GMM_S1_X;
    if (vprot & VCPU_VPROT_WRITEWATCH) s1 &= ~GMM_S1_W;
    return s1;
}


/***********************************************************************
 *           fp_exception_code
 *
 * Trapped floating-point exception (EC 0x2c) -> status, from the ISS flag bits (IOF 0, DZF 1, OFF 2, UFF 3, IXF 4).
 */
static NTSTATUS fp_exception_code( uint64_t esr )
{
    if (esr & 0x02) return STATUS_FLOAT_DIVIDE_BY_ZERO;
    if (esr & 0x04) return STATUS_FLOAT_OVERFLOW;
    if (esr & 0x08) return STATUS_FLOAT_UNDERFLOW;
    if (esr & 0x10) return STATUS_FLOAT_INEXACT_RESULT;
    return STATUS_FLOAT_INVALID_OPERATION;
}


/***********************************************************************
 *           vcpu_exit_to_exception
 *
 * Build the Windows exception for a guest fault exit, as the EL0 signal handlers do from a sigcontext
 * (segv_handler, ill_handler, bus_handler, trap_handler, fpe_handler in signal_arm64.c). frame must hold the full
 * guest state (x0 is read for the fast-fail code). pc_adjust is what trap_handler adds to the context PC before
 * setup_raise_exception (which takes it back off for EXCEPTION_BREAKPOINT). Returns FALSE for exits that are never
 * SEH: a broken invariant (stage-2 abort, nested fault), an unexpected asynchronous exception, an unknown exit.
 */
BOOL vcpu_exit_to_exception( const vel1_exit *e, const struct syscall_frame *frame, EXCEPTION_RECORD *rec,
                             ULONG64 *pc_adjust )
{
    memset( rec, 0, sizeof(*rec) );
    *pc_adjust = 0;
    rec->ExceptionAddress = (void *)e->elr;

    switch (e->kind)
    {
    case VEL1_EXIT_ILLEGAL:  /* foreign hvc / smc */
    case VEL1_EXIT_TRAP:     /* trapped system register access */
        rec->ExceptionCode = STATUS_ILLEGAL_INSTRUCTION;
        return TRUE;
    case VEL1_EXIT_FAULT_SYNC:
        break;
    default:
        return FALSE;
    }

    switch (e->fclass)
    {
    case VEL1_FC_DATA_ABORT:
    case VEL1_FC_INSN_ABORT:
        if (e->fclass == VEL1_FC_DATA_ABORT && (e->esr & 0x3f) == 0x21)  /* DFSC alignment fault */
        {
            rec->ExceptionCode = STATUS_DATATYPE_MISALIGNMENT;
            return TRUE;
        }
        rec->ExceptionCode = STATUS_ACCESS_VIOLATION;
        rec->NumberParameters = 2;
        if (e->fclass == VEL1_FC_INSN_ABORT) rec->ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
        else if (e->esr & 0x40) rec->ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;  /* WnR */
        else rec->ExceptionInformation[0] = EXCEPTION_READ_FAULT;
        rec->ExceptionInformation[1] = e->far;
        return TRUE;
    case VEL1_FC_BRK:
        switch (e->esr & 0xffff)
        {
        case 0xf000:
            rec->ExceptionCode = STATUS_BREAKPOINT;
            rec->NumberParameters = 1;
            *pc_adjust = 4;  /* skip the brk instruction */
            break;
        case 0xf001:
            rec->ExceptionCode = STATUS_ASSERTION_FAILURE;
            break;
        case 0xf003:
            rec->ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
            rec->ExceptionFlags = EXCEPTION_NONCONTINUABLE;
            rec->NumberParameters = 1;
            rec->ExceptionInformation[0] = frame->x[0];
            break;
        case 0xf004:
            rec->ExceptionCode = STATUS_INTEGER_DIVIDE_BY_ZERO;
            break;
        default:
            rec->ExceptionCode = STATUS_ILLEGAL_INSTRUCTION;
            break;
        }
        return TRUE;
    case VEL1_FC_FP_EXC:
        rec->ExceptionCode = fp_exception_code( e->esr );
        return TRUE;
    case VEL1_FC_PC_ALIGN:
    case VEL1_FC_SP_ALIGN:
        rec->ExceptionCode = STATUS_DATATYPE_MISALIGNMENT;
        return TRUE;
    case VEL1_FC_STEP:
    case VEL1_FC_HW_BREAK:
    case VEL1_FC_WATCHPOINT:
        rec->ExceptionCode = STATUS_SINGLE_STEP;
        return TRUE;
    case VEL1_FC_UNDEFINED:
    case VEL1_FC_BTI:
    case VEL1_FC_ILLEGAL_STATE:
    case VEL1_FC_SVC:
    case VEL1_FC_HVC:
    case VEL1_FC_SMC:
    case VEL1_FC_SYSREG:
    case VEL1_FC_FP_ACCESS:
        rec->ExceptionCode = STATUS_ILLEGAL_INSTRUCTION;
        return TRUE;
    default:  /* SError, WFx, anything unclassified */
        return FALSE;
    }
}


static void copy_v( NEON128 *dst, const uint8_t (*src)[16], unsigned int first, unsigned int count )
{
    memcpy( dst + first, src + first, count * sizeof(*dst) );
}


/***********************************************************************
 *           vcpu_frame_from_syscall_exit
 *
 * What __wine_syscall_dispatcher saves (signal_arm64.c): x18-x29, lr = x9, sp, pc = x30, NZCV (which also clears
 * restore_flags), the syscall id in x8, FPCR/FPSR and q0-q31. x0-x17 are not saved.
 */
void vcpu_frame_from_syscall_exit( struct syscall_frame *frame, const vel1_exit *e )
{
    const vel1_regs *r = &e->regs;

    memcpy( frame->x + 18, r->x + 18, 11 * sizeof(frame->x[0]) );
    frame->fp = r->x[29];
    frame->lr = r->x[9];
    frame->sp = r->sp_el1;
    frame->pc = r->x[30];
    frame->cpsr = r->cpsr;
    frame->restore_flags = 0;
    frame->syscall_id = r->x[8];
    frame->fpcr = r->fpcr;
    frame->fpsr = r->fpsr;
    copy_v( frame->v, r->v, 0, 32 );
}


/***********************************************************************
 *           vcpu_frame_from_unix_call_exit
 *
 * What __wine_unix_call_dispatcher saves: x18-x29, q8-q15, lr = pc = x30, sp, NZCV (clearing restore_flags).
 */
void vcpu_frame_from_unix_call_exit( struct syscall_frame *frame, const vel1_exit *e )
{
    const vel1_regs *r = &e->regs;

    memcpy( frame->x + 18, r->x + 18, 11 * sizeof(frame->x[0]) );
    frame->fp = r->x[29];
    frame->lr = r->x[30];
    frame->sp = r->sp_el1;
    frame->pc = r->x[30];
    frame->cpsr = r->cpsr;
    frame->restore_flags = 0;
    copy_v( frame->v, r->v, 8, 8 );
}


/***********************************************************************
 *           vcpu_frame_from_regs
 *
 * The full guest state (a fault or kick exit, VCPU_FULL_CORE_MASK + all q) -> frame.
 */
void vcpu_frame_from_regs( struct syscall_frame *frame, const vel1_regs *r )
{
    memcpy( frame->x, r->x, 29 * sizeof(frame->x[0]) );
    frame->fp = r->x[29];
    frame->lr = r->x[30];
    frame->sp = r->sp_el1;
    frame->pc = r->pc;
    frame->cpsr = r->cpsr;
    frame->restore_flags = 0;
    frame->fpcr = r->fpcr;
    frame->fpsr = r->fpsr;
    copy_v( frame->v, r->v, 0, 32 );
}


/***********************************************************************
 *           vcpu_regs_from_frame
 *
 * frame -> the full guest state, for vel1_regs_set( VCPU_FULL_CORE_MASK, VEL1_R_ALL_SIMD ).
 */
void vcpu_regs_from_frame( vel1_regs *r, const struct syscall_frame *frame )
{
    memcpy( r->x, frame->x, 29 * sizeof(frame->x[0]) );
    r->x[29] = frame->fp;
    r->x[30] = frame->lr;
    r->sp_el1 = frame->sp;
    r->pc = frame->pc;
    r->cpsr = frame->cpsr;
    r->fpcr = frame->fpcr;
    r->fpsr = frame->fpsr;
    memcpy( r->v, frame->v, sizeof(r->v) );
}


/***********************************************************************
 *           vcpu_return_plan
 *
 * The registers a syscall return writes, mirroring __wine_syscall_dispatcher_return: x18-x29, lr, sp, pc and NZCV
 * from the frame always; x0 = the return value, or x0-x17 from the frame with CONTEXT_INTEGER; q0-q31, FPCR and
 * FPSR with CONTEXT_FLOATING_POINT. In the EL0 mode the guest's other registers survive in the host registers across
 * the host C code; in the vCPU mode they survive in the vCPU, except when a nested user callback ran other guest code
 * on it (callback_ran): then the FP state comes back from the frame too.
 */
void vcpu_return_plan( const struct syscall_frame *frame, ULONG64 retval, BOOL callback_ran, vel1_regs *r,
                       uint64_t *core_mask, uint32_t *simd_mask )
{
    *core_mask = VEL1_R_X(0) | VEL1_R_X18_X29 | VEL1_R_X(30) | VEL1_R_SP_EL1 | VEL1_R_PC | VEL1_R_CPSR;
    *simd_mask = 0;

    memcpy( r->x + 18, frame->x + 18, 11 * sizeof(frame->x[0]) );
    r->x[29] = frame->fp;
    r->x[30] = frame->lr;
    r->sp_el1 = frame->sp;
    r->pc = frame->pc;
    r->cpsr = frame->cpsr;
    r->x[0] = retval;

    if (frame->restore_flags & RF_INTEGER)
    {
        memcpy( r->x, frame->x, 18 * sizeof(frame->x[0]) );
        *core_mask |= VEL1_R_GPRS;
    }
    if ((frame->restore_flags & RF_FLOATING_POINT) || callback_ran)
    {
        r->fpcr = frame->fpcr;
        r->fpsr = frame->fpsr;
        memcpy( r->v, frame->v, sizeof(r->v) );
        *core_mask |= VEL1_R_FPCR | VEL1_R_FPSR;
        *simd_mask = VEL1_R_ALL_SIMD;
    }
}

#endif /* __APPLE__ && __aarch64__ */
