/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 the openrosetta / fex_macos contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/*
 * vcpu_el1 — run arm64 guest code (Wine PE code, FEX's libarm64ecfex.dll) at EL1 inside a Hypervisor.framework vCPU.
 *
 * Written fresh for the Wine arm64 vCPU mode (proton-darwin docs/macos/vcpu-m1-wine-vcpu-mode-design-2026-09-23.md,
 * "the design"; openrosetta's reply docs/macos/fex-side-reply-m1-2026-09-23.md, "the reply", Ask 2). Contains no Wine
 * code. Every register value is derived from the fex_macos fork's MIT harness step3b/hvf_fex_vk.cpp ("vk" below,
 * line numbers at fex_macos-sync c09f8c474), which ran it live in every 3a-3d and M:N run. Wine citations ("wine")
 * are to proton wine 9a6e69cf8bc (read for the ABI only).
 *
 * WHAT THIS LIBRARY IS NOT: a memory manager. The caller owns the stage-1 page tables (gmm), the stage-2 mappings,
 * and where the vel1 blob lives in guest memory. vel1 only needs the IPA of the stage-1 root (TTBR0) and the guest VA
 * at which the caller installed the blob.
 *
 * ---------------------------------------------------------------------------------------------------------------
 * DECISIONS (each one is referenced from the code with "[Dn]")
 * ---------------------------------------------------------------------------------------------------------------
 * [D1] hv_* is reached ONLY through a caller-supplied ops table (vel1_hv_ops). vcpu_el1.c has no reference to any
 *      hv_* symbol; vcpu_el1_live.c is the only file that does and exports vel1_hv_live_ops(). Host-only tests link a
 *      stub table and do not link Hypervisor.framework at all (build.sh checks `nm -u` and `otool -L`).
 * [D2] One VM per process. vel1_vm_create(ipa_bits=0) is the PROVEN path (hv_vm_create(NULL)). ipa_bits=40 uses
 *      hv_vm_config_set_ipa_size and has NEVER run (rung R8). A request above hv_vm_config_get_max_ipa_size fails
 *      cleanly before any VM exists. vel1_vm_create also starts the per-VM KICKER thread [D8].
 * [D3] Per-vCPU constants (vk:963-975, identical in MnVcpuWorkerMain vk:1613-1625):
 *        MAIR_EL1  = 0xFF                           attr0 = Normal WB-RA-WA inner+outer (the only attribute used)
 *        TCR_EL1   = 16 | 1<<8 | 1<<10 | 3<<12 | 1<<23 | IPS<<32
 *                    T0SZ=16 (48-bit VA), IRGN0=ORGN0=WB-WA, SH0=inner, TG0=0 (4K), EPD1 (no TTBR1 walks)
 *                    IPS = 2 (40-bit) in every proven run. vel1 derives IPS from the VM's IPA size (32->0, 36->1,
 *                    40->2, 42->3, 44->4, 48->5); for ipa_bits 0 (proven default VM) it keeps the proven 2.
 *        SCTLR_EL1 = 0x30D00800 | M | C | I = 0x30D01805. 0x30D00800 is the RES1 set (bits 11,20,22,23,28,29);
 *                    A=0 and SA=0 (no alignment or SP-alignment checks), WXN=0, BT1=0 (no BTI enforcement at EL1).
 *        CPACR_EL1 = 3<<20 (FPEN: FP/SIMD does not trap; vk:968). SMEN (bits 24-25) stays 0.
 *        ACTLR_EL1 = 2 (bit 1 = EnTSO, hardware TSO; vk:970) and READ BACK (vk:971-975); a mismatch fails the create.
 *                    SDK GATE (Wine M1a, proton-darwin vcpu-m1a-first-light-2026-09-23.md): EnTSO only reads back when
 *                    the HOST BINARY is linked against a current SDK. With `-platform_version macos 11.0 11.0` (the pin
 *                    Wine's EL0 build uses to keep x18) the write is silently dropped, and create returns VEL1_E_ENTSO.
 *                    vCPU mode doesn't need the x18 pin, so link the host with the current SDK. VEL1_CFG_NO_ENTSO is a
 *                    fallback that loses hardware TSO (x86 guests then need FEX's software TSO).
 *        CPSR      = 0x3c5 (M=EL1h, DAIF masked; vk:976).
 *        VBAR_EL1  = the blob's guest VA (vector table at blob offset 0, 2 KiB aligned; vk:967).
 * [D4] Create does NOT call hv_vcpu_set_trap_debug_exceptions: live rung R4a (2026-09-23) proved that with HVF's
 *      default setting BRK (EC 0x3C) is already taken at EL1 through the guest vector. VEL1_CFG_CLEAR_DEBUG_TRAP adds
 *      the call (set_trap_debug_exceptions(false), after the ACTLR read-back) for rung R4b only; it has never run
 *      live. Either way the decoder accepts an EC 0x3C host exit (FAULT_SYNC, via_exit).
 * [D5] The blob (vcpu_el1_blob.S) is one position-independent 4 KiB page image:
 *        +0x000..0x7FF  vector table, 16 slots x 128 B; slot i = { hvc #(VEL1_HVC_VEC_BASE+i); b . }
 *        +0x800         syscall stub   { bti c; hvc #VEL1_HVC_SYSCALL;   ret; udf }
 *        +0x810         unix-call stub { bti c; hvc #VEL1_HVC_UNIX_CALL; ret; udf }
 *        +0x820..0x88F  the TLBI stub [D18] (vel1_run_tlbi only)
 *      The vector touches NO register and NO memory: the host reads ESR/FAR/ELR/SPSR_EL1 (vk:1050-1053) and "plays
 *      eret" by setting PC/CPSR (vk:1080/1137). The proven page used hvc #1 in every slot (vk:1161); a distinct
 *      immediate per slot is new (rung R1 proves reading ISS[15:0]).
 *      PLACEMENT (safety, the 2026-09-21 panic class): vel1_blob_install copies the image into caller memory that
 *      must be PLAIN ANONYMOUS memory; it refuses destination memory that is executable on the host (mach_vm_region).
 *      NEVER hv_vm_map the library's own __TEXT copy (vel1_blob_start): that is executable file-backed memory.
 *      Stage-2 for the blob page should be R|X (not W) and stage-1 read-only + executable at EL1 (PXN=0), outside
 *      every Wine view, mapped once, never unmapped or remapped while a vCPU exists [D7].
 *      Syscalls: Wine's arm64 PE stubs do `mov x8,#id; mov x9,x30; ldr x16,<ptr>; blr x16` (wine
 *      include/wine/asm.h:247-255), NOT svc. The unix side points __wine_syscall_dispatcher at blob+0x800 and the
 *      unix-call dispatcher at blob+0x810 — for arm64ec, the *_arm64ec slot, because wine/loader.c:2039-2043 moves
 *      the arm64ec pointer into __wine_unix_call_dispatcher and puts the unix-side dispatcher in the arm64ec slot.
 * [D6] Exit decoding is pure and table-driven (vel1_raw_needs + vel1_decode + vel1_cancel_decide). vel1_run() is the
 *      only caller of hv_vcpu_run and does the lazy fetches the decoder asks for.
 * [D7] Nested faults / PC inside the blob. The vector touches no data, so the only thing that can fault inside it is
 *      the FETCH of the page, which recurses at EL1 forever with no exit. Mitigation: (a) the page is never changed
 *      while vCPUs exist; (b) the host detects it: a vector exit whose ELR lies in the vector table, or a CANCELED
 *      exit with PC anywhere in the blob except exactly on a slot's/stub's hvc (or the stub's bti), is
 *      VEL1_EXIT_NESTED_FAULT — fatal, never SEH. Only a kick ends the recursion, so a watchdog vel1_kick_remote is
 *      what turns that hang into this exit. (c) After ANY exit that leaves the real PC inside the blob (vector slots
 *      and both stubs), vel1_run refuses to re-enter (VEL1_E_NOT_RESUMED) until the caller writes PC; every PC write
 *      into the blob is refused (VEL1_E_PC_IN_BLOB) except vel1_state_restore of a state saved by vel1_state_save,
 *      and vel1_run_tlbi's own entry into (and restore from) the TLBI stub [D18].
 *      So no path re-enters with PC on an hvc or a `b .`.
 * [D8] Kicks. hv_vcpus_exit is NOT async-signal-safe: it takes Hypervisor.framework's global vcpus os_unfair_lock and
 *      then a per-vCPU pthread_mutex (force_exit_vtimer_wait), and hv_vcpu_run's own entry may take the same global
 *      lock — a handler that interrupted that entry would self-deadlock (reviewer's disassembly, 2026-09-23; the
 *      hvf_sigtest runs passing does not make the window safe). So vel1_kick_self(), for the owning thread's signal
 *      handler, makes NO hv_* call. It:
 *        1. returns VEL1_KICK_NOT_LIVE if the vCPU is not live (G1);
 *        2. sets kick_pending (seq_cst) — FIRST (G2);
 *        3. if in_run is clear, returns VEL1_KICK_FLAG_ONLY (the thread is in host code; see [D15]);
 *        4. else sets kick_req and semaphore_signal()s the per-VM kicker (a Mach trap: async-signal-safe),
 *           returning VEL1_KICK_QUEUED.
 *      The KICKER thread wakes, and for each registered vCPU with kick_req set, takes the vCPU's lifetime lock, checks
 *      live && in_run, and calls hv_vcpus_exit(&id, 1) — the proven cross-thread call exactly as vk:1362-1372.
 *      Cost: one thread wake-up (typically a few us to tens of us, measured by rung R6) on top of the 6.6 us mean
 *      signal->CANCELED the sigtest measured. Dependency: the kicker must be scheduled; it runs at
 *      QOS_CLASS_USER_INTERACTIVE. G3 (vector window) and the in_run/pending handshake are unchanged:
 *        G2 vel1_run sets in_run, THEN checks kick_pending, THEN enters (seq_cst). The kicker reads in_run only after
 *           the semaphore wake, which is after kick_pending was stored, so either vel1_run's check sees the kick or
 *           the kicker sees in_run and cancels (or latches) the run. A CANCELED with no pending kick is a latched
 *           leftover: vel1_run re-enters with no state change (bounded by VEL1_MAX_SPURIOUS_CANCELED).
 *        G3 a CANCELED with PC exactly on a slot's hvc (or a stub's bti/hvc) re-enters without reporting; the kick
 *           stays pending (vk:1493-1527 does the same).
 *      vel1_kick_remote() (any thread, not async-signal-safe) takes the lifetime lock and calls hv_vcpus_exit directly.
 * [D9] Registers: the proven resume is set_reg(PC) + set_reg(CPSR) (vk:1080/1137). Full save/load = 668/643 ns
 *      (75 accessors, README r3c 19) against a 0.25-0.3 us exit, so fetches are per exit kind (vel1_regs_mask_for):
 *        SYSCALL   : Wine's __wine_syscall_dispatcher save set (wine signal_arm64.c:1698-1729): x0-x9, x18-x29, x30,
 *                    SP_EL1, NZCV, FPCR, FPSR, q0-q31 = 59 accessors. APC delivery, wait_suspend,
 *                    NtGetContextThread(self) and exception dispatch all read that frame. The 12-accessor plan
 *                    (x0-x9, x30, sp) is available only with VEL1_CFG_SYSCALL_MINIMAL_UNSAFE: NOT safe for Wine.
 *        UNIX_CALL : Wine's __wine_unix_call_dispatcher save set (wine signal_arm64.c:1869-1885): x0-x9, x18-x29,
 *                    x30, SP_EL1, NZCV, q8-q15 = 33 accessors.
 *        HOSTCALL  : x0-x9, x30, SP_EL1 = 12 (harness use only).
 *        fault/kick: everything except SP_EL0 (vel1_regs_get, caller-driven).
 *      ESR/FAR_EL1 are never WRITTEN (vk:1295-1297). SP_EL0 has never been touched by any run: accessible, unproven.
 * [D10] Returns take their values from the CALLER'S frame, never from vel1's last exit, because a
 *      KeUserModeCallback recursion (the design §5) runs an inner vel1_run loop whose NtCallbackReturn exit replaces
 *      v->last. vel1_syscall_return(v, x0, pc, lr) sets x0, PC := pc (frame->pc = x30 at entry), x30 := lr
 *      (frame->lr = x9 at entry) — the effect of Wine's dispatcher return. vel1_call_return(v, x0, pc) sets x0 and
 *      PC := pc (frame->pc = x30 at entry): the host plays the stub's `ret`. For callbacks, bracket the inner loop
 *      with vel1_state_save/vel1_state_restore (the proven MnSaveImage/MnLoadImage set, vk:1248-1300) or restore the
 *      callee-saved set (x19-x29, sp, q8-q15) from the frame with vel1_regs_set.
 * [D11] EC 0x01 (WFI/WFE trapped to the host): vel1_run steps PC by 4 and re-enters. Never observed (rung R5).
 * [D12] vel1_vcpu is caller-allocated, in HOST-ONLY memory (never in the TEB or any other guest-writable page: PE code
 *      could forge its pointers). Wine keeps a POINTER to it in its per-thread data. A zeroed vel1_vcpu is a valid
 *      "not live" object for vel1_kick_self/vel1_kick_remote. All hv_vcpu_* calls must come from the creating thread;
 *      every vel1 function that reaches one checks it (VEL1_E_WRONG_THREAD).
 * [D13] CPSR sanitising: every CPSR vel1 writes (cfg->cpsr, vel1_resume_at, vel1_regs_set, vel1_return_from_vector)
 *      is (value & NZCV) | 0x3c5 — EL1h, DAIF masked — whatever the caller passed (a Windows CONTEXT must never
 *      switch the vCPU to EL0/EL1t or unmask interrupts). vel1_regs_get hands back NZCV only (the Windows view);
 *      vel1_get_cpsr_raw is the raw accessor. vel1_state_restore writes the saved raw value (it came from the vCPU).
 * [D14] Logical PC. When an exit leaves the real PC in the blob, vel1_regs_get reports the guest's logical context:
 *      vector exits -> PC = ELR_EL1, CPSR = SPSR_EL1's NZCV; stub exits -> PC = x30 (the PE return point, Wine's
 *      frame->pc). No accessor is spent on those.
 * [D15] The syscall-entry kick contract (unbounded deferral otherwise). A kick can be left pending across a returned
 *      exit: (a) FLAG_ONLY, when the signal arrives after vel1_run cleared in_run; (b) G3, when a CANCELED landed on a
 *      stub's hvc and vel1_run re-entered and returned the SYSCALL. If Wine then dispatches a BLOCKING syscall, the
 *      SIGUSR1 is already consumed and a suspend hangs. Contract: after every vel1_run return, Wine (1) marks itself
 *      "in syscall" in its own per-thread state, then (2) calls vel1_kick_take() (seq_cst on both sides); if it
 *      returns true, Wine handles the host request (suspend/APC/abort) BEFORE dispatching. Its signal handler, run on
 *      the same thread, does the mirror image: if the "in syscall" mark is set it takes the existing host path;
 *      otherwise it calls vel1_kick_self. NOTE: Wine's is_inside_syscall (sp inside the kernel stack,
 *      wine unix_private.h:471-475) is ALSO true while the thread is inside hv_vcpu_run (the host thread runs on its
 *      kernel stack), so the handler must branch on vel1_in_guest()/its own mark, not on is_inside_syscall.
 * [D16] Thread exit. vel1_vcpu_destroy must never run from a signal handler that interrupted vel1_run (Wine's
 *      quit_handler -> abort_thread -> pthread_exit, wine signal_arm64.c:1344-1350, would do exactly that): it refuses
 *      with VEL1_E_STATE while in_run is set. Wine must instead set a "quit" mark and vel1_kick_self from the handler,
 *      let vel1_run return KICK, leave the loop, vel1_vcpu_destroy on the thread, and only then abort_thread.
 *      If hv_vcpu_destroy fails the vCPU is not counted as gone: vel1_vm_destroy keeps refusing.
 * [D17] Foreign hvc / smc from PE code is an ILLEGAL exit (Wine raises STATUS_ILLEGAL_INSTRUCTION with PC = the
 *      instruction), not fatal. HOSTCALL immediates (0x8000-0xFFFF) are honoured only when PC lies in the caller's
 *      cfg.hostcall_lo..hi range (harness use); anywhere else they are foreign too. EC 0x18 (trapped MSR/MRS, e.g. an
 *      ID register HVF traps) is a TRAP with the decoded Rt/direction so Wine can emulate or skip it.
 *      The PC an hvc exit reports is taken as the hvc + 4 (VEL1_HVC_PC_IS_NEXT, inferred from the hvf_proto smoke:
 *      re-entering with PC untouched resumes AFTER the hvc; rung R1 measures it and the decoder records it).
 * [D18] The initiator TLBI executor (gmm's "G11"; m1/README.md). vel1_run_tlbi(v, va, n) runs the blob's TLBI stub
 *      (+0x820) on the CALLER'S OWN vCPU, which must be stopped at an exit (any vel1_run return; Wine is then
 *      dispatching a syscall or a fault with its in-syscall mark set [D15]). No second thread, no wake, no slot.
 *      OWNERSHIP: vel1 owns the saved-register contract, because only vel1 knows its own bookkeeping (pc_in_blob,
 *      the logical PC/CPSR [D14], v->last). The gmm backend (Wine's, or m1/m1_exec.c) only decides WHO executes.
 *      THE CONTRACT: the stub reads x0..x(k-1) (VA >> 12, k <= 8 per stub run; n <= 64 per call, run in chunks of 8)
 *      and touches no memory and no other register. vel1 saves exactly what it writes: x0..x(k-1), PC and CPSR
 *      (raw), sets x0..x(k-1), PC = the entry for k, CPSR = 0x3c5, runs to the stub's `hvc #0x102`, checks that
 *      exit (EC 0x16, imm 0x102, PC == stub hvc + 4), and restores the saved values raw — the one other documented
 *      bypass of [D7]/[D13] besides vel1_state_restore. pc_in_blob, the logical PC/CPSR and v->last are untouched,
 *      so the caller's frame and every resume helper behave exactly as if the stub had never run.
 *      COST: 3k + 7 accessors + one exit round trip (n = 1: 10 accessors).
 *      ELR/SPSR (the vector-window question, reply Ask 2): the rule forbids switching the vCPU while it is INSIDE
 *      the window (exception taken, the slot's hvc not yet executed). vel1_run normally re-enters in that state
 *      (G3), but after 64 spurious cancels it can return VEL1_EXIT_CANCELED without looking at PC, so the argument
 *      does NOT rest on the window: it rests on the stub never taking an exception, so the stub may run even while ELR_EL1 /
 *      SPSR_EL1 / ESR_EL1 / FAR_EL1 hold a latched fault (a FAULT_SYNC exit: Wine's write-watch handler lowers
 *      nothing but RAISES a valid descriptor, which the eager policy shoots down). The stub cannot clobber them:
 *      only an EL1 exception writes them, and nothing in the stub can take one — every fetch is from the blob page,
 *      which the vCPU already fetches for its vector and never changes [D7]; dsb/isb/tlbi do not fault at EL1 (HVF
 *      does not trap TLBI: gmm G3b/G4b/G9); hvc exits to EL2; DAIF is masked (CPSR 0x3c5) and the vtimer is an EL2
 *      exit. So vel1 does NOT save/restore them; it VERIFIES the assumption instead: any exit other than the stub's
 *      own hvc at the expected PC — a vector hvc, a stage-2 abort, any other EC — returns VEL1_E_STUB, which is
 *      fatal: the vCPU is left unresumable (NOT_RESUMED) and nothing is restored, so it can never resume with a
 *      clobbered ELR/SPSR.
 *      KICKS: in_run is set around each stub hv_vcpu_run (as vel1_run does), so the kicker and vel1_kick_remote can
 *      exit it; a watchdog can still end a (never expected) stuck stub. A CANCELED inside the stub — latched or
 *      from a kick — is absorbed: vel1 reads PC (it must lie in the stub, else VEL1_E_STUB), sets PC back to the
 *      chunk's entry and re-enters, re-issuing every TLBI of the chunk and its final `dsb ish` on whichever PE runs
 *      it. kick_pending is NEVER consumed here: the kick stays pending and the caller's next vel1_run reports it
 *      (KICK, before entering). More than VEL1_MAX_SPURIOUS_CANCELED cancels in one chunk: the state is restored and
 *      VEL1_E_BUSY returned (the shootdown did not complete; the caller uses another executor).
 *      NOT BUILT: the whole-VMID form (`tlbi vmalle1is`, gmm's n > 64 request): it has never run in a vCPU, so there
 *      is no stub for it and n > 64 is VEL1_E_ARG.
 */
#ifndef VCPU_EL1_H
#define VCPU_EL1_H

#include <os/lock.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- constants [D3] ---------------------------------------------------------------------------------------- */
#define VEL1_MAIR_EL1 0xFFull
#define VEL1_TCR_EL1_BASE (16ull | (1ull << 8) | (1ull << 10) | (3ull << 12) | (1ull << 23))
#define VEL1_TCR_EL1(ips) (VEL1_TCR_EL1_BASE | ((uint64_t)(ips) << 32))
#define VEL1_TCR_IPS_PROVEN 2u
#define VEL1_SCTLR_EL1 (0x30D00800ull | (1ull << 0) | (1ull << 2) | (1ull << 12))
#define VEL1_CPACR_EL1 (3ull << 20)
#define VEL1_ACTLR_EL1_ENTSO 2ull
#define VEL1_CPSR_EL1H_MASKED 0x3c5ull
#define VEL1_CPSR_NZCV_MASK 0xF0000000ull
#define VEL1_HVC_PC_IS_NEXT 1 /* [D17] */

/* ---- the blob [D5] ------------------------------------------------------------------------------------------ */
#define VEL1_BLOB_PAGE 0x1000u
#define VEL1_VECTORS_OFF 0x000u
#define VEL1_VECTORS_SIZE 0x800u
#define VEL1_VECTOR_SLOT_SIZE 0x80u
#define VEL1_SYSCALL_STUB_OFF 0x800u
#define VEL1_UNIXCALL_STUB_OFF 0x810u
#define VEL1_STUB_SIZE 0x10u
#define VEL1_STUB_HVC_INSN 1u /* instruction index of the hvc inside a stub (0 = bti c) */
#define VEL1_STUB_RET_INSN 2u
/* [D18] the TLBI stub: 8 entries `dsb ish; b t_k` (entry for k VAs at +0x820 + (8-k)*8), the chain of 8
   `tlbi vale1is, x7..x0`, then `dsb ish; isb; hvc #0x102; b .` */
#define VEL1_TLBI_STUB_OFF 0x820u
#define VEL1_TLBI_ENTRY_SIZE 8u
#define VEL1_TLBI_REGS 8u      /* VAs per stub run: x0..x7 */
#define VEL1_TLBI_HVC_OFF 0x888u
#define VEL1_TLBI_STUB_END 0x890u
#define VEL1_TLBI_MAX_VA 64u   /* per vel1_run_tlbi call; gmm asks for the (unbuilt) whole-VMID form above 64 */
#define VEL1_TLBI_ENTRY_OFF(k) (VEL1_TLBI_STUB_OFF + (VEL1_TLBI_REGS - (k)) * VEL1_TLBI_ENTRY_SIZE)

#define VEL1_HVC_SYSCALL 0x0100u
#define VEL1_HVC_UNIX_CALL 0x0101u
#define VEL1_HVC_TLBI_DONE 0x0102u /* [D18] the TLBI stub's hvc (foreign, i.e. ILLEGAL, if vel1_run ever sees it) */
#define VEL1_HVC_VEC_BASE 0x0200u /* + slot 0..15 */
#define VEL1_HVC_USER_MIN 0x8000u /* 0x8000..0xFFFF: HOSTCALL, only inside cfg.hostcall_lo..hi [D17] */

extern const uint8_t vel1_blob_start[];
extern const uint8_t vel1_blob_end[];
size_t vel1_blob_size(void);
/* Copies the blob into dst (4 KiB aligned, >= 4 KiB, PLAIN ANONYMOUS host memory), zero-fills the rest of the page and
   invalidates the I-cache. Refuses (VEL1_E_EXEC_MEMORY) a destination whose host mapping is executable — the
   library's own __TEXT copy, MAP_JIT memory or any other executable mapping [D5]. */
int vel1_blob_install(void* dst, size_t dst_size);

/* ---- errors ----------------------------------------------------------------------------------------------- */
enum {
  VEL1_OK = 0,
  VEL1_E_ARG = -1,
  VEL1_E_STATE = -2,       /* VM/vCPU state wrong; destroy/run from a handler that interrupted vel1_run [D16] */
  VEL1_E_HV = -3,          /* an hv_* call failed; see the hv_err field / v->last_hv_err */
  VEL1_E_IPA_TOO_BIG = -4,
  VEL1_E_ENTSO = -5,
  VEL1_E_WRONG_THREAD = -6,
  VEL1_E_NOT_RESUMED = -7, /* vel1_run while the real PC is still in the blob [D7] */
  VEL1_E_PC_IN_BLOB = -8,  /* a PC write into the blob [D7] */
  VEL1_E_EXEC_MEMORY = -9, /* vel1_blob_install: destination is executable host memory [D5] */
  VEL1_E_NO_KICKER = -10,  /* the kicker thread or its semaphore could not be created */
  VEL1_E_STUB = -11,       /* [D18] the TLBI stub ended in an unexpected exit: FATAL, the vCPU is left NOT_RESUMED */
  VEL1_E_BUSY = -12,       /* [D18] too many CANCELEDs inside the stub: state restored, shootdown NOT done */
};

/* ---- the hv ops table [D1] -------------------------------------------------------------------------------- */
typedef struct vel1_hv_ops {
  const char* name;
  int32_t (*vm_get_max_ipa)(uint32_t* bits);
  int32_t (*vm_get_default_ipa)(uint32_t* bits);
  int32_t (*vm_create)(uint32_t ipa_bits); /* 0 = hv_vm_create(NULL) (proven); else config + set_ipa_size */
  int32_t (*vm_destroy)(void);
  int32_t (*vcpu_create)(uint64_t* id, void** hv_exit);
  int32_t (*vcpu_destroy)(uint64_t id);
  int32_t (*vcpu_run)(uint64_t id);
  int32_t (*vcpus_exit)(uint64_t* ids, uint32_t n); /* called from the kicker thread or vel1_kick_remote only [D8] */
  int32_t (*get_reg)(uint64_t id, uint32_t reg, uint64_t* v);
  int32_t (*set_reg)(uint64_t id, uint32_t reg, uint64_t v);
  int32_t (*get_sys_reg)(uint64_t id, uint16_t reg, uint64_t* v);
  int32_t (*set_sys_reg)(uint64_t id, uint16_t reg, uint64_t v);
  int32_t (*get_simd)(uint64_t id, uint32_t reg, uint8_t out[16]);
  int32_t (*set_simd)(uint64_t id, uint32_t reg, const uint8_t in[16]);
  int32_t (*set_trap_debug_exceptions)(uint64_t id, bool trap);
} vel1_hv_ops;

const vel1_hv_ops* vel1_hv_live_ops(void); /* vcpu_el1_live.c */

/* ---- VM [D2] -------------------------------------------------------------------------------------------------- */
typedef struct {
  uint32_t max_ipa_bits;
  uint32_t default_ipa_bits; /* queried only when ipa_bits != 0 (hv_vm_config_get_default_ipa_size is unproven) */
  uint32_t ipa_bits, tcr_ips;
  int32_t hv_err;
} vel1_vm_info;

int vel1_vm_create(const vel1_hv_ops* ops, uint32_t ipa_bits, vel1_vm_info* info);
int vel1_vm_destroy(void); /* refuses while any vCPU is live (or failed to destroy); joins the kicker */
int vel1_ips_for_ipa_bits(uint32_t ipa_bits);

/* ---- registers [D9] ------------------------------------------------------------------------------------- */
typedef struct {
  uint64_t x[31];
  uint64_t sp_el0, sp_el1, pc, cpsr, fpcr, fpsr, tpidr_el0, tpidrro_el0;
  uint8_t v[32][16];
} vel1_regs;

#define VEL1_R_X(n) (1ull << (n))
#define VEL1_R_GPRS 0x7FFFFFFFull
#define VEL1_R_X0_X9 0x3FFull
#define VEL1_R_X18_X29 (0xFFFull << 18)
#define VEL1_R_PC (1ull << 32)
#define VEL1_R_CPSR (1ull << 33) /* NZCV only on reads, sanitised on writes [D13] */
#define VEL1_R_SP_EL0 (1ull << 34)
#define VEL1_R_SP_EL1 (1ull << 35)
#define VEL1_R_FPCR (1ull << 36)
#define VEL1_R_FPSR (1ull << 37)
#define VEL1_R_TPIDR_EL0 (1ull << 38)
#define VEL1_R_TPIDRRO_EL0 (1ull << 39)
#define VEL1_R_ALL_CORE (VEL1_R_GPRS | VEL1_R_PC | VEL1_R_CPSR | VEL1_R_SP_EL0 | VEL1_R_SP_EL1 | VEL1_R_FPCR | \
                         VEL1_R_FPSR | VEL1_R_TPIDR_EL0 | VEL1_R_TPIDRRO_EL0)
#define VEL1_R_ALL_SIMD 0xFFFFFFFFu
#define VEL1_R_Q8_Q15 0x0000FF00u

/* ---- exits [D6] ----------------------------------------------------------------------------------------- */
typedef enum {
  VEL1_EXIT_NONE = 0,
  VEL1_EXIT_SYSCALL,      /* syscall stub; exit.regs holds the dispatcher save set [D9]; x8 = id, x9 = caller LR */
  VEL1_EXIT_UNIX_CALL,    /* unix-call stub; exit.regs holds the unix dispatcher save set */
  VEL1_EXIT_HOSTCALL,     /* hvc #0x8000-0xFFFF inside cfg.hostcall_lo..hi; PC untouched resumes after the hvc */
  VEL1_EXIT_FAULT_SYNC,   /* sync exception at EL1 (vector sync slot), or a debug-EC exit (via_exit) [D4] */
  VEL1_EXIT_ASYNC,        /* the vector's IRQ/FIQ/SError slot (DAIF masked: unexpected) */
  VEL1_EXIT_ILLEGAL,      /* foreign hvc / smc [D17]: elr = the instruction, spsr = CPSR */
  VEL1_EXIT_STAGE2_ABORT, /* exit EC 0x20/0x24: broken gmm invariant; FATAL, never SEH */
  VEL1_EXIT_TRAP,         /* other exception exits (EC 0x18 sysreg: sysreg_* fields; elr = the instruction) */
  VEL1_EXIT_CANCELED,     /* decoder: HV_EXIT_REASON_CANCELED. vel1_run returns it only past the spurious bound */
  VEL1_EXIT_KICK,         /* vel1_run only: a kick was pending; guest state is precise and outside the blob */
  VEL1_EXIT_VTIMER,       /* decoder only; vel1_run re-enters (vk:1040-1043) */
  VEL1_EXIT_NESTED_FAULT, /* fault inside / stuck in the blob [D7]; FATAL */
  VEL1_EXIT_UNKNOWN,      /* unknown exit reason, or a vector exit without its syndrome */
  VEL1_EXIT_ERROR,        /* an hv or vel1 usage error: exit.err / exit.hv_err */
  VEL1_EXIT__COUNT
} vel1_exit_kind;

typedef enum {
  VEL1_FC_NONE = 0,
  VEL1_FC_UNDEFINED,     /* EC 0x00 */
  VEL1_FC_WFX,           /* 0x01 */
  VEL1_FC_FP_ACCESS,     /* 0x07, 0x19 (SVE), 0x1D (SME) */
  VEL1_FC_BTI,           /* 0x0D */
  VEL1_FC_ILLEGAL_STATE, /* 0x0E */
  VEL1_FC_SVC,           /* 0x15 */
  VEL1_FC_HVC,           /* 0x16 */
  VEL1_FC_SMC,           /* 0x17 */
  VEL1_FC_SYSREG,        /* 0x18 */
  VEL1_FC_INSN_ABORT,    /* 0x20, 0x21 */
  VEL1_FC_PC_ALIGN,      /* 0x22 */
  VEL1_FC_DATA_ABORT,    /* 0x24, 0x25 */
  VEL1_FC_SP_ALIGN,      /* 0x26 */
  VEL1_FC_FP_EXC,        /* 0x28, 0x2C */
  VEL1_FC_SERROR,        /* 0x2F */
  VEL1_FC_HW_BREAK,      /* 0x30, 0x31 */
  VEL1_FC_STEP,          /* 0x32, 0x33 */
  VEL1_FC_WATCHPOINT,    /* 0x34, 0x35 */
  VEL1_FC_BRK,           /* 0x3C */
  VEL1_FC_OTHER,
  VEL1_FC__COUNT
} vel1_fault_class;

typedef enum {
  VEL1_FSC_NA = 0,
  VEL1_FSC_ADDR_SIZE,    /* 0x00-0x03 */
  VEL1_FSC_TRANSLATION,  /* 0x04-0x07 */
  VEL1_FSC_ACCESS_FLAG,  /* 0x08-0x0B */
  VEL1_FSC_PERMISSION,   /* 0x0C-0x0F */
  VEL1_FSC_EXTERNAL,     /* 0x10, 0x14-0x17 */
  VEL1_FSC_ALIGNMENT,    /* 0x21 */
  VEL1_FSC_TLB_CONFLICT, /* 0x30 */
  VEL1_FSC_OTHER
} vel1_fsc_class;

typedef enum { VEL1_VEC_SYNC = 0, VEL1_VEC_IRQ = 1, VEL1_VEC_FIQ = 2, VEL1_VEC_SERROR = 3 } vel1_vec_type;
typedef enum { VEL1_VEC_CUR_SP0 = 0, VEL1_VEC_CUR_SPX = 1, VEL1_VEC_LOWER_A64 = 2, VEL1_VEC_LOWER_A32 = 3 } vel1_vec_group;

typedef struct {
  vel1_exit_kind kind;
  int32_t err;
  int32_t hv_err;
  uint32_t hv_reason;
  uint32_t hvc_imm;
  uint64_t exit_syndrome, exit_va, exit_ipa;
  uint32_t exit_ec;
  bool have_pc;
  bool hvc_pc_is_next; /* hvc exits: PC read == hvc + 4 */
  uint64_t pc;         /* the REAL PC read after the exit */
  /* FAULT_SYNC / ASYNC / NESTED / ILLEGAL / TRAP: the interrupted context. elr = where it happened (resume point for
     vector exits), spsr = raw SPSR_EL1 (or CPSR for via_exit/ILLEGAL/TRAP); nzcv = spsr & NZCV. */
  bool via_exit;
  uint32_t vec_slot;
  vel1_vec_group vec_group;
  vel1_vec_type vec_type;
  uint64_t esr, far, elr, spsr, nzcv;
  uint32_t ec;
  vel1_fault_class fclass;
  vel1_fsc_class fsc_class;
  uint8_t fsc, fsc_level;
  bool far_valid, is_write, s1ptw;
  uint16_t iss_imm;
  /* TRAP with EC 0x18 */
  bool sysreg_is_read;
  uint8_t sysreg_rt;
  uint32_t sysreg_enc; /* op0<<14 | op1<<11 | crn<<7 | crm<<3 | op2 (the MRS/MSR encoding) */
  /* SYSCALL / UNIX_CALL / HOSTCALL: what vel1_run fetched (regs_core / regs_simd say which fields are valid; CPSR is
     NZCV only). regs.pc is the logical PC (x30) for stub exits. */
  vel1_regs regs;
  uint64_t regs_core;
  uint32_t regs_simd;
} vel1_exit;

#define VEL1_HAVE_PC 1u
#define VEL1_HAVE_CPSR 2u
#define VEL1_HAVE_EL1SYN 4u
typedef struct {
  uint32_t reason;
  uint64_t syndrome, va, ipa;
  uint32_t have;
  uint64_t pc, cpsr, esr_el1, far_el1, elr_el1, spsr_el1;
} vel1_raw_exit;

typedef struct {
  uint64_t blob_va;                 /* == VBAR_EL1 */
  uint64_t hostcall_lo, hostcall_hi; /* [lo, hi): where HOSTCALL immediates are honoured; 0,0 = nowhere */
} vel1_layout;

uint32_t vel1_raw_needs(const vel1_raw_exit* raw, const vel1_layout* lay);
void vel1_decode(const vel1_raw_exit* raw, const vel1_layout* lay, vel1_exit* out);
vel1_fault_class vel1_fault_class_of_ec(uint32_t ec);
vel1_fsc_class vel1_fsc_class_of(uint32_t fsc);
const char* vel1_exit_kind_name(vel1_exit_kind k);
const char* vel1_fault_class_name(vel1_fault_class c);
bool vel1_pc_in_blob(uint64_t pc, const vel1_layout* lay);

typedef enum {
  VEL1_CANCEL_SPURIOUS = 0,   /* no kick pending: re-enter unchanged */
  VEL1_CANCEL_REPORT_KICK,    /* report the kick; PC is ordinary guest code */
  VEL1_CANCEL_REENTER_WINDOW, /* PC exactly on a slot's hvc or a stub's bti/hvc: re-enter, keep the kick pending */
  VEL1_CANCEL_NESTED_FATAL    /* PC anywhere else in the blob, or PC+ELR both in the table [D7] */
} vel1_cancel_action;
vel1_cancel_action vel1_cancel_decide(bool kick_pending, uint64_t pc, bool have_elr, uint64_t elr,
                                      const vel1_layout* lay);
bool vel1_cancel_needs_elr(uint64_t pc, const vel1_layout* lay);

/* ---- vCPU ------------------------------------------------------------------------------------------------ */
#define VEL1_CFG_NO_ENTSO 1u
/* 2u was VEL1_CFG_KEEP_DEBUG_TRAP_DEFAULT: keeping HVF's debug-trap default is now the default (R4a) [D4]. */
#define VEL1_CFG_KEEP_DEBUG_TRAP_DEFAULT 2u /* deprecated no-op, accepted for old callers */
#define VEL1_CFG_SYSCALL_MINIMAL_UNSAFE 4u /* 12-accessor SYSCALL plan; NOT safe for Wine [D9] */
#define VEL1_CFG_CLEAR_DEBUG_TRAP 8u /* adds hv_vcpu_set_trap_debug_exceptions(false); NEVER run live (R4b) [D4] */

typedef struct {
  uint64_t ttbr0;
  uint64_t blob_va; /* 4 KiB aligned; becomes VBAR_EL1 */
  uint64_t sp_el1;
  uint64_t pc;      /* must not be inside the blob */
  uint64_t cpsr;    /* only NZCV is taken [D13] */
  uint64_t x0;
  uint64_t hostcall_lo, hostcall_hi; /* [D17]; 0,0 = no HOSTCALL anywhere */
  uint32_t flags;
} vel1_vcpu_cfg;

#define VEL1_MAX_SPURIOUS_CANCELED 64u
#define VEL1_LOGICAL_PC 1u
#define VEL1_LOGICAL_CPSR 2u
#define VEL1_MAX_VCPUS 64u

typedef struct {
  uint64_t runs, exits, vtimer, canceled_spurious, canceled_window, wfx_stepped, kicks_reported;
  uint64_t kick_queued, kick_flag_only, kick_not_live, kick_wrong_thread, kick_signal_failed, kick_remote_sent;
  uint64_t kicker_exits; /* hv_vcpus_exit calls the kicker thread made for this vCPU */
  uint64_t tlbi_calls, tlbi_runs, tlbi_canceled, tlbi_vtimer; /* [D18] vel1_run_tlbi */
} vel1_stats;

/* Caller-allocated in host-only memory; zero it before first use [D12]. Fields are private. */
typedef struct vel1_vcpu {
  const vel1_hv_ops* ops;
  uint64_t id;
  void* hv_exit;
  pthread_t owner;
  vel1_layout lay;
  uint32_t flags;
  _Atomic int live;         /* G1 */
  _Atomic int in_run;       /* G2 */
  _Atomic int kick_pending; /* G2 */
  _Atomic int kick_req;     /* [D8] for the kicker */
  os_unfair_lock life_lock;
  bool destroy_failed;
  bool pc_in_blob;          /* [D7] the real PC is in the blob until the caller writes PC */
  uint8_t logical_valid;    /* [D14] VEL1_LOGICAL_PC | VEL1_LOGICAL_CPSR */
  uint64_t logical_pc, logical_cpsr;
  int32_t last_hv_err;
  vel1_exit last;
  _Atomic uint64_t kick_queued, kick_flag_only, kick_not_live, kick_wrong_thread, kick_signal_failed,
      kick_remote_sent, kicker_exits;
  uint64_t runs, exits, vtimer, canceled_spurious, canceled_window, wfx_stepped, kicks_reported;
  /* [D18] appended: vel1_run_tlbi counters, and what an unexpected stub exit looked like (VEL1_E_STUB) */
  uint64_t tlbi_calls, tlbi_runs, tlbi_canceled, tlbi_vtimer;
  uint32_t tlbi_bad_reason;
  uint64_t tlbi_bad_syndrome, tlbi_bad_pc;
} vel1_vcpu;

int vel1_vcpu_create(vel1_vcpu* v, const vel1_vcpu_cfg* cfg);
int vel1_vcpu_destroy(vel1_vcpu* v); /* owning thread, NOT from a handler that interrupted vel1_run [D16] */

vel1_exit_kind vel1_run(vel1_vcpu* v, vel1_exit* out);

/* ---- resume helpers [D10] -------------------------------------------------------------------------------- */
int vel1_resume_at(vel1_vcpu* v, uint64_t pc, uint64_t cpsr);          /* PC, sanitised CPSR [D13] */
int vel1_return_from_vector(vel1_vcpu* v);                             /* PC := last ELR, CPSR := last SPSR (sanitised) */
int vel1_syscall_return(vel1_vcpu* v, uint64_t x0, uint64_t pc, uint64_t lr); /* x0; PC := pc; x30 := lr */
int vel1_call_return(vel1_vcpu* v, uint64_t x0, uint64_t pc);          /* x0; PC := pc (plays the stub's ret) */
int vel1_hostcall_return(vel1_vcpu* v, uint64_t x0);                   /* x0; PC untouched (after the hvc) */

/* ---- registers ------------------------------------------------------------------------------------------ */
int vel1_regs_get(vel1_vcpu* v, vel1_regs* r, uint64_t core_mask, uint32_t simd_mask); /* logical PC/CPSR [D14] */
int vel1_regs_set(vel1_vcpu* v, const vel1_regs* r, uint64_t core_mask, uint32_t simd_mask);
int vel1_get_cpsr_raw(vel1_vcpu* v, uint64_t* cpsr);
/* The per-kind plan: what vel1_run fetches for call kinds (in), what the matching return writes (out). flags = cfg
   flags (VEL1_CFG_SYSCALL_MINIMAL_UNSAFE selects the cheap SYSCALL plan). Pure. */
void vel1_regs_mask_for(vel1_exit_kind k, uint32_t flags, uint64_t* core_in, uint32_t* simd_in, uint64_t* core_out,
                        uint32_t* simd_out);
unsigned vel1_regs_accessor_count(uint64_t core_mask, uint32_t simd_mask);

/* Full vCPU state around a nested (KeUserModeCallback) inner loop [D10]. The proven MnSaveImage set (75 reads) and
   MnLoadImage set (73 writes; ESR/FAR are never written), plus vel1's own per-exit bookkeeping. */
typedef struct {
  uint64_t x[31], pc, cpsr_raw, fpcr, fpsr, sp_el1, tpidr_el0, tpidrro_el0, tpidr_el1, elr_el1, spsr_el1, esr_el1,
      far_el1;
  uint8_t v[32][16];
  bool pc_in_blob;
  uint8_t logical_valid;
  uint64_t logical_pc, logical_cpsr;
  vel1_exit last;
  bool valid;
} vel1_state;
int vel1_state_save(vel1_vcpu* v, vel1_state* s);
int vel1_state_restore(vel1_vcpu* v, const vel1_state* s);

/* ---- the initiator TLBI executor [D18] ---------------------------------------------------------------------- */
/* On the owning thread, with the vCPU stopped at an exit (not from a handler inside vel1_run): `tlbi vale1is` for
   each of va[0..n-1] (n = 1..VEL1_TLBI_MAX_VA; ASID 0), then `dsb ish; isb`, executed by this vCPU. On VEL1_OK every
   VA is invalidated on every PE of the inner-shareable domain and the vCPU's registers, PC, CPSR and vel1's
   bookkeeping are exactly as before; a pending kick is still pending. VEL1_E_STATE / VEL1_E_WRONG_THREAD /
   VEL1_E_ARG / VEL1_E_BUSY: nothing to undo, the shootdown was not (or not certainly) done, use another executor.
   VEL1_E_STUB: fatal for the vCPU (left NOT_RESUMED). VEL1_E_HV: fatal; if it failed while SAVING (before any write)
   the vCPU is untouched and not marked NOT_RESUMED, otherwise it is left NOT_RESUMED. (Review 2026-09-23 #5.) */
int vel1_run_tlbi(vel1_vcpu* v, const uint64_t* va, size_t n);

/* ---- kicks [D8][D15] ------------------------------------------------------------------------------------ */
typedef enum {
  VEL1_KICK_QUEUED = 0,     /* in guest: kick_pending set, the kicker was signalled (it calls hv_vcpus_exit) */
  VEL1_KICK_FLAG_ONLY,      /* live but in host code: kick_pending set, nothing else; see [D15] */
  VEL1_KICK_NOT_LIVE,       /* no vCPU: nothing done */
  VEL1_KICK_WRONG_THREAD,   /* vel1_kick_self on a thread that does not own v: nothing done */
  VEL1_KICK_SIGNAL_FAILED,  /* semaphore_signal failed (kick_pending is still set) */
  VEL1_KICK_SENT            /* vel1_kick_remote only: hv_vcpus_exit issued directly */
} vel1_kick_result;
vel1_kick_result vel1_kick_self(vel1_vcpu* v);   /* async-signal-safe; no hv_* call */
vel1_kick_result vel1_kick_remote(vel1_vcpu* v); /* any thread; lifetime lock + direct hv_vcpus_exit */
bool vel1_kick_pending(vel1_vcpu* v);
bool vel1_kick_take(vel1_vcpu* v);  /* [D15]: atomically consume a pending kick */
bool vel1_in_guest(vel1_vcpu* v);   /* in_run: the thread is inside (or about to enter) hv_vcpu_run */

void vel1_get_stats(vel1_vcpu* v, vel1_stats* s);

#ifdef __cplusplus
}
#endif
#endif /* VCPU_EL1_H */
