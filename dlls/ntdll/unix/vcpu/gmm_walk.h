// SPDX-License-Identifier: MIT
//
// gmm_walk — the software AArch64 stage-1 walker, i.e. the oracle. §1/§3 N2/N3/N8. Pure translation: given a
// TTBR0 (an IPA) and a way to turn an intermediate-table IPA into a host pointer, walks 4K-granule descriptors
// exactly as hardware would, for TCR_EL1.T0SZ in the 16..39 range this prototype cares about (2, 3 or 4 levels).
//
// This header has NO dependency on gmm_t — gmm_walk_raw() is used directly against page tables gmm never built
// (N2: rung_vm.c's build_page_tables() and step3b/hvf_fex_vk.cpp's GuestMirror::SetPTE()), which is the whole
// point of an oracle: it must be trustworthy independent of the code under test.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Software tags carried in bits [3:1] of an INVALID (bit0==0) leaf descriptor. Hardware ignores these bits
// entirely when bit0==0; gmm uses them so gmm_walk can report *why* a translation faults without consulting gmm's
// region tree. §0: "PAGE_NOACCESS, PAGE_GUARD, reserved and decommitted pages are INVALID descriptors ... the
// other bits are software tags."
enum {
  GMM_TAG_RESERVED = 0,     // never committed (also: default-zeroed memory, i.e. "never touched")
  GMM_TAG_NOACCESS = 1,
  GMM_TAG_GUARD = 2,
  GMM_TAG_DECOMMITTED = 3,
};
#define GMM_TAG_SHIFT 1
#define GMM_TAG_MASK 0x7ull  // bits [3:1]; bit0 (valid) is separate

// A translation, as reported by the walker. On a fault, `level` is the level at which the walk stopped (the level
// whose descriptor was found invalid, or 3 if a leaf permission would apply — permission is not itself a fault in
// this walker; it just reports the bits and lets the caller decide, matching how gmm_fault separately classifies).
typedef struct {
  int valid;        // 1 = resolved to a valid leaf (block or page); 0 = translation fault
  int level;         // level of the resolving/failing descriptor: 0..3 (block leaves stop at 1 or 2; RESERVED
                       // stage-1 tables here only ever produce level-3 page leaves, see §2 "no blocks")
  uint64_t ipa;        // valid: leaf output address, page/block-aligned, OR'd with the VA's in-page offset.
                         // invalid: 0 (see `tag`)
  unsigned tag;          // invalid only: GMM_TAG_* from bits[3:1] of the failing descriptor
  int ap_ro;               // valid only: AP[2]
  int uxn, pxn;             // valid only
  int ng, af, sh;            // valid only: raw bits, for tests that want to check attribute plumbing
} gmm_xlat_t;

// Reads the 4K-aligned table at `table_ipa` and returns a host pointer to it (readable for at least 4096 bytes),
// or NULL if `table_ipa` cannot be resolved to host memory (walker then reports a GMM_F_BUG-shaped hard failure
// via valid=0, level=-1 — this should never happen against a correctly built tree; N2/N3 assert it never does).
typedef const void *(*gmm_table_reader_fn)(void *ctx, uint64_t table_ipa);

// Raw walk, independent of any gmm_t. `t0sz` selects the starting level exactly as TCR_EL1.T0SZ would (VA bits =
// 64-t0sz; levels used = ceil((VAbits-12)/9); start level = 4-levels). Supports table descriptors at levels 0-2,
// block descriptors at levels 1-2 (2 MiB at level 2, 1 GiB at level 1 — only used by N2's external tables; gmm's
// own tables never emit them, §2), and page descriptors at level 3.
void gmm_walk_raw(uint64_t ttbr0_ipa, unsigned t0sz, uint64_t va, gmm_table_reader_fn read_table, void *ctx,
                   gmm_xlat_t *out);

// Starting table level for a given T0SZ (VA bits = 64-t0sz; 0 = 4 levels/48-bit down to 3 = level-3-only/<=21-bit).
// Shared by gmm_walk_raw() and gmm.c's own page-table builder so the two can never disagree about level count.
int gmm_start_level_for_t0sz(unsigned t0sz);

// Pure encode/decode helpers, shared by gmm.c (encoder) and gmm_walk.c (decoder) and exercised directly by N1.
// vprot/overlay use the GMM_PAGE_*/GMM_OVERLAY_* bits from gmm.h; gmm_walk.h intentionally does not include
// gmm.h (no gmm_t dependency), so these take plain unsigned bitmasks with the same numeric values.
uint64_t gmm_pte_encode(unsigned page_prot, unsigned overlay, uint64_t ipa);
// Decodes any 64-bit descriptor as if it were a level-3 leaf (valid page or invalid+tag). Used by gmm_walk_raw's
// leaf case and directly by N1.
void gmm_pte_decode_leaf(uint64_t desc, gmm_xlat_t *out);

#ifdef __cplusplus
}
#endif
