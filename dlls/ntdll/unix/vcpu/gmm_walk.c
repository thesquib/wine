// SPDX-License-Identifier: MIT
//
// gmm_walk.c — the oracle. No hv_*, no gmm_t dependency in gmm_walk_raw()/gmm_pte_encode()/gmm_pte_decode_leaf();
// gmm_walk() (the gmm_t-bound convenience wrapper) lives in gmm.c since it needs gmm_t's internals.
#include "gmm_walk.h"

#define OA_MASK 0x0000fffffffff000ull  // bits[47:12] — output-address field at page granularity
#define AP2_BIT (1ull << 7)
#define AF_BIT (1ull << 10)
#define NG_BIT (1ull << 11)
#define PXN_BIT (1ull << 53)
#define UXN_BIT (1ull << 54)

void gmm_pte_decode_leaf(uint64_t desc, gmm_xlat_t *out) {
  if (!(desc & 1ull)) {
    out->valid = 0;
    out->ipa = 0;
    out->tag = (unsigned)((desc >> GMM_TAG_SHIFT) & GMM_TAG_MASK);
    out->ap_ro = out->uxn = out->pxn = out->ng = out->af = out->sh = 0;
    return;
  }
  out->valid = 1;
  out->tag = 0;
  out->ipa = desc & OA_MASK;
  out->ap_ro = (desc & AP2_BIT) ? 1 : 0;
  out->uxn = (desc & UXN_BIT) ? 1 : 0;
  out->pxn = (desc & PXN_BIT) ? 1 : 0;
  out->ng = (desc & NG_BIT) ? 1 : 0;
  out->af = (desc & AF_BIT) ? 1 : 0;
  out->sh = (int)((desc >> 8) & 0x3);
}

uint64_t gmm_pte_encode(unsigned page_prot, unsigned overlay, uint64_t ipa) {
  const unsigned base = page_prot & 0xFFu;
  const unsigned mod = page_prot & 0xF00u;
  const unsigned GUARD = 0x100u, ARM64CODE = 0x800u;
  const unsigned NOACCESS = 0x01u;
  const unsigned WATCH_OR_SMC = 0x1u | 0x2u;  // GMM_OVERLAY_WRITEWATCH | GMM_OVERLAY_SMC, numerically

  if ((mod & GUARD) || base == NOACCESS || base == 0) {
    // Invalid descriptor + software tag. GUARD takes priority over NOACCESS if (incorrectly) both are set, since
    // a guard page's whole point is to fire exactly once and become the underlying (non-NOACCESS) protection.
    const unsigned tag = (mod & GUARD) ? GMM_TAG_GUARD : GMM_TAG_NOACCESS;
    return ((uint64_t)tag << GMM_TAG_SHIFT);  // bit0 = 0
  }

  const unsigned writable_bits = 0x04u /*READWRITE*/ | 0x08u /*WRITECOPY*/ | 0x40u /*EXECUTE_READWRITE*/ |
                                  0x80u /*EXECUTE_WRITECOPY*/;
  const int writable = (base & writable_bits) != 0;
  const int ro = !writable || (overlay & WATCH_OR_SMC) != 0;
  // Wine M1 / D1 rule (2026-09-23): FEX and arm64ec code run natively at EL1, so every PAGE_EXECUTE* page is
  // EL1-fetchable (PXN=0), x86 code pages included; ARM64CODE additionally forces PXN=0 on a non-EXECUTE page.
  const unsigned exec_bits = 0x10u /*EXECUTE*/ | 0x20u /*EXECUTE_READ*/ | 0x40u /*EXECUTE_READWRITE*/ |
                             0x80u /*EXECUTE_WRITECOPY*/;
  const int arm64code = (mod & ARM64CODE) != 0 || (base & exec_bits) != 0;

  uint64_t d = 0x3ull;               // bits[1:0] = 11: valid, page (level 3) / table (level <3, unused here)
  d |= (0x3ull << 8);                // SH = inner shareable
  d |= AF_BIT;                       // AF = 1
  if (ro) d |= AP2_BIT;              // AP[2] = 1 (read-only)
  d |= UXN_BIT;                      // UXN = 1 always (§2)
  if (!arm64code) d |= PXN_BIT;      // PXN = 1 unless the page is EL1-executable (PAGE_EXECUTE* or ARM64CODE)
  d |= (ipa & OA_MASK);
  return d;
}

int gmm_start_level_for_t0sz(unsigned t0sz) {
  const int vabits = 64 - (int)t0sz;
  if (vabits > 39) return 0;
  if (vabits > 30) return 1;
  if (vabits > 21) return 2;
  return 3;
}

void gmm_walk_raw(uint64_t ttbr0_ipa, unsigned t0sz, uint64_t va, gmm_table_reader_fn read_table, void *ctx,
                   gmm_xlat_t *out) {
  out->valid = 0;
  out->ipa = 0;
  out->tag = GMM_TAG_RESERVED;
  out->level = -1;
  out->ap_ro = out->uxn = out->pxn = out->ng = out->af = out->sh = 0;

  uint64_t table_ipa = ttbr0_ipa;
  for (int level = gmm_start_level_for_t0sz(t0sz); level <= 3; level++) {
    const void *host = read_table(ctx, table_ipa);
    if (!host) {
      // A table IPA the reader cannot resolve to host memory. Never valid against a correctly built tree; N2/N3
      // treat this as a hard test failure, not a translation fault.
      out->level = -1;
      out->tag = GMM_TAG_RESERVED;
      return;
    }
    const int shift = 12 + 9 * (3 - level);
    const unsigned idx = (unsigned)((va >> shift) & 0x1FFull);
    const uint64_t desc = ((const uint64_t *)host)[idx];

    if (!(desc & 1ull)) {
      out->valid = 0;
      out->level = level;
      out->tag = (unsigned)((desc >> GMM_TAG_SHIFT) & GMM_TAG_MASK);
      return;
    }
    const unsigned low2 = (unsigned)(desc & 0x3ull);

    if (level == 3) {
      if (low2 != 0x3u) {  // bits[1:0]=01 at L3 is a reserved/invalid encoding
        out->valid = 0;
        out->level = 3;
        out->tag = GMM_TAG_RESERVED;
        return;
      }
      gmm_pte_decode_leaf(desc, out);
      out->level = 3;
      out->ipa |= (va & 0xFFFull);
      return;
    }

    if (low2 == 0x3u) {  // table descriptor: descend
      table_ipa = desc & OA_MASK;
      continue;
    }
    // low2 == 0x1: block descriptor, a leaf at this level (only levels 1-2 in practice for 4K granule).
    gmm_pte_decode_leaf(desc, out);
    out->level = level;
    const uint64_t block_bytes = 1ull << shift;
    out->ipa |= (va & (block_bytes - 1));
    return;
  }
}
