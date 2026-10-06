// SPDX-License-Identifier: MIT
//
// vel1_acqrel: host-side emulation of misaligned (16-byte-crossing) acquire/release accesses, for a vCPU fault loop.
// Host-only C11; no Hypervisor.framework, no FEX dependency.
//
// Guarantees: a 16-byte-crossing access cannot be single-copy atomic on arm64. The emulated access may tear under a
// concurrent writer, the same as FEX's existing emulation (two acquire loads) and the hardware's own plain unaligned
// access. The ordering matches the instruction:
//   LDAR:  dmb ish; plain load; dmb ishld        (RCsc)
//   LDAPR: plain load; dmb ishld                 (RCpc)
//   STLR:  dmb ish; plain store
// Where the access stays inside a 16-byte granule, LSE2 makes the plain access single-copy atomic, but those do not
// fault in the first place.
#ifndef VEL1_ACQREL_H
#define VEL1_ACQREL_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { VEL1_AR_LDAR = 1, VEL1_AR_LDAPR = 2, VEL1_AR_STLR = 3 };

typedef struct vel1_acqrel {
  uint8_t kind;  // VEL1_AR_LDAR, VEL1_AR_LDAPR (incl. LDAPUR, zero-extending), VEL1_AR_STLR (incl. STLUR)
  uint8_t size;  // 2, 4 or 8 bytes
  uint8_t rt;    // 0..31 (31 = zero register)
  uint8_t rn;    // 0..31 (31 = SP)
  int16_t imm;   // signed byte offset (0 for LDAR/LDAPR/STLR; imm9 for LDAPUR/STLUR)
} vel1_acqrel;

// Returns 1 for LDAR/LDAPR/LDAPUR(zero-extending)/STLR/STLUR with size 2/4/8, else 0 (byte forms, sign-extending
// LDAPURS*, LDLAR/STLLR, exclusives, everything else).
int vel1_acqrel_decode(uint32_t insn, vel1_acqrel* out);

// True iff [addr, addr+size) crosses a 16-byte boundary.
int vel1_acqrel_crosses16(uint64_t addr, uint32_t size);

// Perform the access at host address p with the instruction's ordering. Loads return the value zero-extended from
// size; stores write the low size bytes of value (return 0).
uint64_t vel1_acqrel_perform(const vel1_acqrel* d, void* p, uint64_t value);

#ifdef __cplusplus
}
#endif
#endif
