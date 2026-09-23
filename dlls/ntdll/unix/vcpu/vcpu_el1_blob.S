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
_vel1_blob_end:
