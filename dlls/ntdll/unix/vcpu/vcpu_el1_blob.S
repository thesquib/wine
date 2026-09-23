// SPDX-License-Identifier: MIT
// Copyright (c) 2026 the openrosetta / fex_macos contributors. See vcpu_el1.h for the full MIT text.
//
// The vel1 guest page image [D5]. Data, never executed on the host: the caller copies it (vel1_blob_install) into a
// 4 KiB guest page mapped read-only + executable at EL1, and points VBAR_EL1 at it.
//
//   +0x000  16 x 128 B vector slots: `hvc #(0x200 + slot); b .`  (the proven page is `hvc #1; b .` in every slot,
//           step3b/hvf_fex_vk.cpp:1159-1163; only the immediate differs). The vector clobbers nothing.
//   +0x800  syscall stub:   bti c; hvc #0x100; ret; udf #0
//   +0x810  unix-call stub: bti c; hvc #0x101; ret; udf #0
//   +0x820  TLBI stub [D18] (vel1_run_tlbi only; never reached by PE code in a correct program):
//           8 entries e_k (k = 8..1, 8 bytes each): `dsb ish; b t_k`
//           +0x860 chain t_8..t_1: `tlbi vale1is, x(k-1)` (t_k falls through to t_1), then
//           `dsb ish; isb; hvc #0x102; b .` — the proven G9 stub's sequence (gmm_guest.S _gmm_g9_tlbi) with the
//           VAs in x0..x7 instead of a mailbox. Touches no memory and no register but reads x0..x(k-1).
//   +0x890  whole-VMID TLBI entry [D18] (vel1_run_tlbi_all only; gmm's all=1): `dsb ish; tlbi vmalle1is; dsb ish;
//           isb; hvc #0x102; b .` (hvc at +0x8A0; the blob ends at +0x8A8). Touches no memory and reads no register.
//           Everything before +0x890 is byte-identical to the vel1-gmm-v1 blob.
//
// Immediates must match VEL1_HVC_* in vcpu_el1.h; build.sh disassembles this object and checks every slot.

  .section __TEXT,__const
  .p2align 12
  .globl _vel1_blob_start
  .globl _vel1_blob_end
_vel1_blob_start:

  .irp slot, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
  .p2align 7
  hvc #(0x200 + \slot)
  b .
  .endr

  .p2align 11
_vel1_syscall_stub:
  hint #34            // bti c
  hvc #0x100
  ret
  udf #0
_vel1_unixcall_stub:
  hint #34            // bti c
  hvc #0x101
  ret
  udf #0
_vel1_tlbi_stub:
  .irp k, 8,7,6,5,4,3,2,1
  dsb ish
  b Lvel1_tlbi_t\k
  .endr
Lvel1_tlbi_t8:
  tlbi vale1is, x7
Lvel1_tlbi_t7:
  tlbi vale1is, x6
Lvel1_tlbi_t6:
  tlbi vale1is, x5
Lvel1_tlbi_t5:
  tlbi vale1is, x4
Lvel1_tlbi_t4:
  tlbi vale1is, x3
Lvel1_tlbi_t3:
  tlbi vale1is, x2
Lvel1_tlbi_t2:
  tlbi vale1is, x1
Lvel1_tlbi_t1:
  tlbi vale1is, x0
  dsb ish
  isb
_vel1_tlbi_hvc:
  hvc #0x102
  b .
_vel1_tlbi_all:       // +0x890: the whole-VMID entry (vel1_run_tlbi_all only)
  dsb ish
  tlbi vmalle1is
  dsb ish
  isb
_vel1_tlbi_all_hvc:   // +0x8A0
  hvc #0x102
  b .
_vel1_blob_end:
